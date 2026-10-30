"""Minimal, dependency-free ASCII table renderer.

Replaces ``terminaltables`` (unmaintained since 2019) with the small subset of
functionality grapheneX actually uses. Cells are wrapped, ANSI escapes are not
counted when computing widths, and output is plain text so it is readable by
screen readers and in redirected/piped output.
"""

from __future__ import annotations

import re
import textwrap

ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _width(text: str) -> int:
    return len(ANSI_RE.sub("", text))


def _wrap(text, width):
    lines = []
    for raw_line in str(text).splitlines() or [""]:
        wrapped = textwrap.wrap(
            raw_line, width=max(8, width), break_long_words=True, break_on_hyphens=False
        )
        lines.extend(wrapped or [""])
    return lines


def render_table(headers, rows, max_col_width=48, indent="") -> str:
    """Render ``rows`` as an ASCII table.

    ``headers`` is a sequence of column titles, ``rows`` a sequence of
    sequences. Long cells are wrapped to ``max_col_width`` characters.
    """

    rows = [["" if cell is None else str(cell) for cell in row] for row in rows]
    columns = len(headers)
    widths = [max(8, min(max_col_width, _width(str(header)))) for header in headers]
    for row in rows:
        for index in range(min(columns, len(row))):
            longest = max((_width(part) for part in str(row[index]).splitlines()), default=0)
            widths[index] = min(max_col_width, max(widths[index], min(longest, max_col_width)))

    def border(char="-"):
        return indent + "+" + "+".join(char * (width + 2) for width in widths) + "+"

    def render_row(cells):
        wrapped = [_wrap(cell, widths[index]) for index, cell in enumerate(cells)]
        height = max(len(lines) for lines in wrapped)
        output = []
        for line_index in range(height):
            parts = []
            for column_index, lines in enumerate(wrapped):
                value = lines[line_index] if line_index < len(lines) else ""
                padding = " " * (widths[column_index] - _width(value))
                parts.append(" " + value + padding + " ")
            output.append(indent + "|" + "|".join(parts) + "|")
        return output

    lines = [border(), *render_row(headers), border("=")]
    for row in rows:
        lines.extend(render_row(row + [""] * (columns - len(row))))
    lines.append(border())
    return "\n".join(lines)
