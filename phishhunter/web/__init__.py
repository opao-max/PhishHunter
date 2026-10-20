"""PhishHunter web console (FastAPI).

The package intentionally does not import ``app`` here: importing the web
module should remain cheap and must not require optional dependencies until a
server actually starts.
"""

from __future__ import annotations

__all__: list[str] = []