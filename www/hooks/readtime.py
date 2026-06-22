"""Fill an estimated reading time wherever a page carries the <!--readtime-->
placeholder. Counts prose words, skipping fenced code blocks and HTML, so the
figure recomputes on every build and stays accurate as the article changes.
"""

import math
import re

WPM = 200


def on_page_markdown(markdown, **kwargs):
    if "<!--readtime-->" not in markdown:
        return markdown
    text = re.sub(r"```.*?```", " ", markdown, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    words = len(re.findall(r"[0-9A-Za-z]+", text))
    minutes = max(1, math.ceil(words / WPM))
    return markdown.replace("<!--readtime-->", f" · {minutes} min read")
