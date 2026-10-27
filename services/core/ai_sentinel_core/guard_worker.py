"""One offline native inference process, speaking JSON lines over private pipes."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .guard import Classifier


def main() -> None:
    classifier = Classifier(Path(sys.argv[1]))
    for line in sys.stdin:
        text = json.loads(line)
        if not isinstance(text, str):
            raise ValueError("Expected command text")
        result = classifier.inspect(text)
        print(json.dumps(result), flush=True)
        del text, line


if __name__ == "__main__":
    main()
