"""Run normalized binary-analysis inference through an OpenAI-compatible API."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import cast

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    from aegislm.datasets.binary import BinaryPromptMessage
    from aegislm.inference.binary import GenerateBinaryResponse, run_binary_inference
    from aegislm.inference.openai_compatible import (
        make_openai_compatible_response_generator,
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000/v1")
    parser.add_argument("--api-key-env", default="AEGISLM_API_KEY")
    parser.add_argument("--max-new-tokens", type=int, default=1024)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--request-timeout", type=float, default=300.0)
    args = parser.parse_args()

    source_generator = make_openai_compatible_response_generator(
        base_url=args.base_url,
        model_id=args.model_id,
        max_new_tokens=args.max_new_tokens,
        temperature=args.temperature,
        timeout_seconds=args.request_timeout,
        api_key=os.environ.get(args.api_key_env),
    )

    def binary_generator(messages: list[BinaryPromptMessage]) -> str:
        return source_generator(cast(list, messages))

    count = run_binary_inference(
        dataset_path=args.dataset,
        predictions_path=args.predictions,
        model_id=args.model_id,
        run_id=args.run_id,
        generate_response=cast(GenerateBinaryResponse, binary_generator),
        generation_metadata={
            "backend": "openai-compatible",
            "base_url": args.base_url,
            "temperature": args.temperature,
            "max_new_tokens": args.max_new_tokens,
        },
    )
    print(
        f"AegisLM binary inference complete: records={count}, "
        f"predictions={args.predictions}"
    )


if __name__ == "__main__":
    main()
