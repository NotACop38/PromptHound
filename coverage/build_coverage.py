"""Compatibility entrypoint; the implementation is prompthound.coverage."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompthound.coverage import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
