"""Pinned, offline experimental classifier. Unavailable/partial scans fail closed."""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import subprocess
import sys
from pathlib import Path
from typing import Any

MODEL_ID = "viavoice/mdeberta-ru-prompt-injection"
REVISION = "8e0fdb567ad0d1ddac0c9c1819b182204db26867"
THRESHOLD = 0.999
POLICY_VERSION = "cowrie-command-v1"
FILES = {
    "model.onnx": "06127dcc0e54f65c0efb685b1c2bb26302a7894ff09b126a0a3add687e513af2",
    "tokenizer.json": (
        "17f480544dfe3d4286205dfa15cf35ae1a176ce33383ed4e7286923b441a98b7"
    ),
    "config.json": "c8dcb6a3d7df3e61d80d5dd7854a16d512b12ccf45dee2408eae271e3d7829df",
    "tokenizer_config.json": (
        "1b075d7b6fde47a69bd3d642ddb359f030a88958a1b14d5dc9d9cdf5e673b8ac"
    ),
    "special_tokens_map.json": (
        "63cd5b53789b3b5ae2c3d7aa377bcba1557ff0b41dc69ce07b94350ea32291c2"
    ),
}


class Classifier:
    def __init__(self, directory: Path | None) -> None:
        self.directory = directory
        self.session: Any = None
        self.tokenizer: Any = None
        self.numpy: Any = None
        self.load_failed = False

    def load(self) -> None:
        if self.directory is None:
            raise ValueError("Model not configured")
        for name, expected in FILES.items():
            digest = hashlib.sha256()
            with (self.directory / name).open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            if digest.hexdigest() != expected:
                raise ValueError("Model integrity check failed")
        # Optional runtime dependencies are deliberately absent from the base
        # image and developer environment. No from_pretrained/network loader.
        runtime = importlib.import_module("onnxruntime")
        self.numpy = importlib.import_module("numpy")
        tokenizer = importlib.import_module("tokenizers")
        options = runtime.SessionOptions()
        options.intra_op_num_threads = 2
        options.inter_op_num_threads = 1
        self.tokenizer = tokenizer.Tokenizer.from_file(
            str(self.directory / "tokenizer.json")
        )
        self.tokenizer.enable_truncation(max_length=256, stride=64)
        self.session = runtime.InferenceSession(
            str(self.directory / "model.onnx"),
            sess_options=options,
            providers=["CPUExecutionProvider"],
        )

    def inspect(self, text: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "error",
            "score": None,
            "threshold": THRESHOLD,
            "model_id": MODEL_ID,
            "revision": REVISION,
            "policy_version": POLICY_VERSION,
            "window_count": 0,
            "reason_code": "model_not_configured"
            if self.directory is None
            else "model_unavailable",
        }
        if self.directory is None or self.load_failed:
            return result
        if self.session is None:
            try:
                self.load()
            except Exception:
                self.load_failed = True
                return result
        try:
            encoded = self.tokenizer.encode(text)
            scores = []
            for window in [encoded, *encoded.overflowing]:
                inputs = {
                    "input_ids": self.numpy.array([window.ids], dtype=self.numpy.int64),
                    "attention_mask": self.numpy.array(
                        [window.attention_mask], dtype=self.numpy.int64
                    ),
                }
                logits = [float(v) for v in self.session.run(None, inputs)[0][0]]
                if len(logits) != 2 or not all(math.isfinite(v) for v in logits):
                    raise ValueError("Invalid classifier output")
                maximum = max(logits)
                values = [math.exp(v - maximum) for v in logits]
                scores.append(values[1] / sum(values))
            score = max(scores)
            result.update(
                status="blocked" if score >= THRESHOLD else "no_match",
                score=score,
                window_count=len(scores),
                reason_code="prompt_injection_detected"
                if score >= THRESHOLD
                else "no_injection_detected",
            )
        except Exception:
            result.update(status="error", score=None, reason_code="scan_failed")
        return result


class Guard:
    """Keep native model initialization/inference out of the HTTP process GIL."""

    def __init__(self, directory: Path | None) -> None:
        self.directory = directory
        self.process: subprocess.Popen[str] | None = None
        self.failed = False

    def inspect(self, text: str) -> dict[str, Any]:
        unavailable = Classifier(None).inspect(text)
        if self.directory is None:
            return unavailable
        unavailable["reason_code"] = "model_unavailable"
        if self.failed:
            return unavailable
        try:
            if self.process is None:
                self.process = subprocess.Popen(  # noqa: S603
                    [
                        sys.executable,
                        "-m",
                        "ai_sentinel_core.guard_worker",
                        str(self.directory),
                    ],
                    cwd=Path(__file__).resolve().parents[1],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                )
            if self.process.stdin is None or self.process.stdout is None:
                raise RuntimeError("Guard pipe unavailable")
            self.process.stdin.write(json.dumps(text, ensure_ascii=False) + "\n")
            self.process.stdin.flush()
            result = json.loads(self.process.stdout.readline(8192))
            if not isinstance(result, dict) or result.get("status") not in (
                "blocked",
                "no_match",
                "error",
            ):
                raise ValueError("Invalid Guard result")
            if (
                result.get("revision") != REVISION
                or result.get("threshold") != THRESHOLD
            ):
                raise ValueError("Unexpected Guard configuration")
            # The worker is local trusted code, but a partial/non-finite score
            # must never become a successful Guard check.
            if result["status"] != "error":
                score = result.get("score")
                if (
                    not isinstance(score, (int, float))
                    or not math.isfinite(score)
                    or not 0 <= score <= 1
                ):
                    raise ValueError("Invalid Guard score")
            return result
        except Exception:
            self.failed = True
            self.close()
            return unavailable

    def close(self) -> None:
        if self.process is None:
            return
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        if self.process.stdout is not None:
            self.process.stdout.close()
        self.process = None
