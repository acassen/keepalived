#!/usr/bin/env python3
"""Render the keepalived.conf(5) troff man page into Material for MkDocs markdown.

The man page in the keepalived source tree stays the maintained reference, so
this script is meant to be re-run after each release to refresh the page. It only
understands the small troff subset that keepalived.conf.5 actually uses: .TH, .SH,
.PP, .br, .sp, .nf/.fi, .RS/.RE, .I and the \\fB \\fI \\fR font escapes.

Fill mode is the crux. A preformatted block opens on .nf and closes on .fi or .RE,
but .PP and .SH also reset to fill mode, so prose that the source leaves inside an
.nf region still renders as prose. Within a left margin section, an indented run is
treated as an example block, whereas a section whose body is wholly indented keeps
that text as ordinary prose.
"""

import re
import sys

SRC = "keepalived/doc/man/man5/keepalived.conf.5"
OUT = "keepalived/doc/docs/documentation/keepalived-conf.md"

# Content free macros that may sit inside a preformatted block.
NOISE = {".nf", ".RS", ".br", ".sp"}


def resolve_backslashes(s):
    """Turn the troff backslash escapes into their printed characters."""
    s = s.replace("\\-", "-")
    s = s.replace("\\(aq", "'")
    s = s.replace("\\'", "'")
    s = s.replace("\\ ", " ")
    s = s.replace("\\e", "\\")
    s = s.replace("\\\\", "\\")
    return s


def code_text(s):
    """Plain literal text for a preformatted block."""
    s = re.sub(r"\\f[BIRP]", "", s)
    s = s.replace("\\&", "")
    return resolve_backslashes(s)


def emph(m, mark):
    """Wrap a font span in markdown emphasis, keeping any padding outside."""
    inner = m.group(2)
    if not inner:
        return m.group(1) + m.group(3)
    return m.group(1) + mark + inner + mark + m.group(3)


def inline(s):
    """Markdown for a prose run: fonts to emphasis, escapes resolved, html safe."""
    s = s.replace("\\&", "")
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace("*", r"\*").replace("`", r"\`")
    s = re.sub(r"\\fB(\s*)(.*?)(\s*)\\fR", lambda m: emph(m, "**"), s)
    s = re.sub(r"\\fI(\s*)(.*?)(\s*)\\fR", lambda m: emph(m, "*"), s)
    s = re.sub(r"\\f[BIRP]", "", s)
    return resolve_backslashes(s)


class Page:
    """Accumulate markdown while folding troff fill mode into paragraphs."""

    def __init__(self):
        self.out = []
        self.fill = []           # words of the current visual line
        self.vlines = []         # visual lines of the current paragraph
        self.indent = ""         # set while inside the leading note admonition
        self.section_indented = None  # is the current section body left indented

    def end_vline(self):
        if self.fill:
            self.vlines.append(" ".join(self.fill))
            self.fill = []

    def flush(self):
        self.end_vline()
        if not self.vlines:
            return
        block = inline("\n".join(self.vlines)).replace("\n", "  \n")
        for ln in block.split("\n"):
            self.out.append(self.indent + ln if ln else "")
        self.out.append("")
        self.vlines = []

    def text(self, line):
        self.fill.append(line.strip())

    def heading(self, level, title):
        self.out.append(f"{level} {title}")
        self.out.append("")

    def code(self, lines):
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        if not lines:
            return
        self.out.append(self.indent + "```")
        for c in lines:
            self.out.append(self.indent + c if c else "")
        self.out.append(self.indent + "```")
        self.out.append("")


def take_code(lines, i, n):
    """Collect a preformatted block; stop at .fi/.RE (consume) or .PP/.SH (keep)."""
    block = []
    while i < n:
        cur = lines[i]
        s = cur.strip()
        if s in (".fi", ".RE"):
            i += 1
            break
        if s == ".PP" or cur.startswith(".SH"):
            break
        if s in NOISE:
            i += 1
            continue
        block.append(code_text(cur.rstrip()))
        i += 1
    return block, i


def take_example(lines, i, n):
    """Collect an indented example run inside a left margin section."""
    block = []
    while i < n:
        cur = lines[i]
        if cur[:1] == ".":
            break
        if cur.strip() == "":
            block.append("")
            i += 1
            continue
        if cur[:1] not in (" ", "\t"):
            break
        block.append(cur.rstrip())
        i += 1
    return block, i


def convert(lines):
    page = Page()
    i, n = 0, len(lines)

    while i < n:
        raw = lines[i]
        line = raw.rstrip()

        if line.startswith(".TH"):
            m = re.match(r"\.TH\s+(\S+)\s+(\S+)", line)
            page.out.append(
                f"<!-- Generated from {m.group(1)}.{m.group(2)} by "
                "tools/man2md.py. Do not edit by hand. -->"
            )
            page.out.append("")
            page.heading("#", f"{m.group(1)}({m.group(2)})")
            i += 1
            continue

        if line.startswith(".SH"):
            page.flush()
            page.indent = ""
            page.section_indented = None
            title = resolve_backslashes(re.sub(r"\\f[BIRP]", "", line[3:].strip().strip('"')))
            if title == "NAME":
                i += 1
                continue
            if title.rstrip(":") == "Note":
                page.out.append("!!! note")
                page.out.append("")
                page.indent = "    "
                i += 1
                continue
            page.heading("##" if title.isupper() else "###", title)
            i += 1
            continue

        if line == ".nf":
            page.flush()
            block, i = take_code(lines, i + 1, n)
            page.code(block)
            continue

        if line == ".PP" or line == ".sp":
            page.flush()
            i += 1
            continue

        if line == ".br":
            page.end_vline()
            i += 1
            continue

        if line in (".RS", ".RE", ".fi"):
            i += 1
            continue

        if line.startswith(".I "):
            page.flush()
            page.out.append(page.indent + inline("\\fI" + line[3:].strip() + "\\fR"))
            page.out.append("")
            i += 1
            continue

        if line == "":
            page.flush()
            i += 1
            continue

        indented = raw[:1] in (" ", "\t")
        if page.section_indented is None:
            page.section_indented = indented
        if indented and page.section_indented is False:
            page.flush()
            block, i = take_example(lines, i, n)
            page.code(block)
            continue

        page.text(line)
        i += 1

    page.flush()
    return page.out


def main():
    with open(SRC) as f:
        lines = f.read().split("\n")
    out = convert(lines)
    text = "\n".join(out)
    text = re.sub(r"\n{3,}", "\n\n", text).rstrip() + "\n"
    with open(OUT, "w") as f:
        f.write(text)
    print(f"wrote {OUT} ({text.count(chr(10))} lines)")


if __name__ == "__main__":
    sys.exit(main())
