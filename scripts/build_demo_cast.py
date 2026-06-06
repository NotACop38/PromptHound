#!/usr/bin/env python3
"""Build an animated terminal-cast SVG for the README from the captured demo run.

The output renders inline on GitHub (CSS keyframes play when an SVG is used as
an <img> source) and reveals the demo output line by line, with a blinking
cursor, so the README shows the offline demo "in action" without shipping a
binary GIF.

The SVG is derived directly from ``docs/assets/demo_output.txt`` so the two can
never drift; colors are assigned by a small content heuristic that mirrors the
project's banner/coverage palette. Refresh after re-capturing the demo::

    python demo/run_demo.py --seed 0 > docs/assets/demo_output.txt
    python scripts/build_demo_cast.py
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "assets" / "demo_output.txt"
OUT = ROOT / "docs" / "assets" / "demo.svg"

# Nord-ish palette, matched to the project banner/coverage graphics.
BG = "#2e3440"
BAR = "#252a35"
FG = "#d8dee9"
DIM = "#3b4252"
CYAN = "#88c0d0"
BLUE = "#81a1c1"
GREEN = "#a3be8c"
YELLOW = "#ebcb8b"
MUTED = "#8a93a3"

WIDTH = 1136
TOP = 52.0  # baseline of the first text row
STEP = 18.0  # line height
DURATION = 18  # seconds per loop
REVEAL_END = 88  # percent of the loop spent revealing lines; rest is hold


def color_for(line: str) -> str | None:
    """Pick a fill color for one captured output line (None = blank spacer)."""
    s = line.strip()
    if not s:
        return None
    if line.startswith("PromptHound:"):
        return YELLOW
    if set(s) == {"─"} or line.startswith("  ─"):
        return DIM  # full-width section rule / table separator
    if re.match(r"^\d+\. ", line):
        return CYAN  # numbered section title
    if s.startswith("Demo complete") or "rules fired" in s:
        return GREEN
    if (
        s.startswith("→ wrote")
        or s.startswith("file://")
        or s == "Open the visual coverage map in a browser:"
    ):
        return BLUE
    return FG


def sanitize(line: str) -> str:
    """Replace the machine-specific file:// path with a generic one for docs."""
    return re.sub(r"file://.*?/out/coverage", "file:///path/to/PromptHound/out/coverage", line)


def esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def main() -> None:
    lines = SRC.read_text(encoding="utf-8").splitlines()
    n = len(lines)
    height = int(TOP + STEP * n + 24)

    keyframes: list[str] = []
    texts: list[str] = []
    for i, raw in enumerate(lines):
        reveal_at = round((i + 1) / n * REVEAL_END, 3)
        keyframes.append(
            f"  .l{i}{{animation:r{i} {DURATION}s steps(1,end) infinite}}\n"
            f"  @keyframes r{i}{{0%,{reveal_at}%{{opacity:0}}"
            f"{min(reveal_at + 0.4, 100)}%,100%{{opacity:1}}}}"
        )
        color = color_for(raw)
        if color is None:
            continue
        y = TOP + STEP * i
        content = esc(sanitize(raw))
        texts.append(
            f'  <text class="l{i}" x="22" y="{y:.1f}" fill="{color}" '
            f'xml:space="preserve">{content}</text>'
        )

    # Cursor blinks at the prompt position once output has finished rendering.
    cursor_y = TOP + STEP * n
    keyframes.append(
        f"  .cur{{animation:appear {DURATION}s steps(1,end) infinite,"
        "blink 1s steps(1,end) infinite}\n"
        f"  @keyframes appear{{0%,{REVEAL_END}%{{opacity:0}}"
        f"{REVEAL_END + 0.4}%,100%{{opacity:1}}}}\n"
        "  @keyframes blink{0%,49%{opacity:1}50%,100%{opacity:0}}"
    )

    style = "\n".join(keyframes)
    body = "\n".join(texts)
    font = "SFMono-Regular,Consolas,Menlo,monospace"
    title = "make demo · python demo/run_demo.py --seed 0"

    svg = "\n".join(
        [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}"'
            f' height="{height}" viewBox="0 0 {WIDTH} {height}"'
            f' font-family="{font}" font-size="13">',
            f"  <style>\n{style}\n  </style>",
            f'  <rect width="{WIDTH}" height="{height}" rx="10" fill="{BG}"/>',
            f'  <rect width="{WIDTH}" height="34" rx="10" fill="{BAR}"/>',
            f'  <rect y="20" width="{WIDTH}" height="14" fill="{BAR}"/>',
            '  <circle cx="20" cy="17" r="6" fill="#bf616a"/>',
            '  <circle cx="40" cy="17" r="6" fill="#ebcb8b"/>',
            '  <circle cx="60" cy="17" r="6" fill="#a3be8c"/>',
            f'  <text x="{WIDTH // 2}" y="22" fill="{MUTED}" font-size="12"'
            f' text-anchor="middle">{title}</text>',
            body,
            f'  <rect class="cur" x="22" y="{cursor_y - 11:.1f}" width="8"'
            f' height="14" fill="{GREEN}"/>',
            "</svg>",
            "",
        ]
    )
    OUT.write_text(svg, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({height}px tall, {n} lines)")


if __name__ == "__main__":
    main()
