# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Split a PostgreSQL script into statements.

The RDS Data API runs one statement per call, so the SQL files are split on top-level semicolons.
Semicolons inside string literals, quoted identifiers, comments and dollar-quoted bodies
(function definitions) are not split points.
"""
import re

_DOLLAR_TAG = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")


def split_statements(script):
    statements, buf, i, n = [], [], 0, len(script)
    while i < n:
        ch = script[i]
        nxt = script[i + 1] if i + 1 < n else ""
        if ch == "-" and nxt == "-":                      # line comment
            j = script.find("\n", i)
            j = n if j == -1 else j
            buf.append(script[i:j]); i = j
        elif ch == "/" and nxt == "*":                    # block comment (may nest)
            depth, j = 1, i + 2
            while j < n and depth:
                if script.startswith("/*", j):
                    depth += 1; j += 2
                elif script.startswith("*/", j):
                    depth -= 1; j += 2
                else:
                    j += 1
            if depth:
                raise ValueError("unterminated block comment")
            buf.append(script[i:j]); i = j
        elif ch in ("'", '"'):                            # string literal or quoted identifier
            j = i + 1
            while True:
                k = script.find(ch, j)
                if k == -1:
                    raise ValueError("unterminated quoted text")
                if k + 1 < n and script[k + 1] == ch:     # doubled quote is an escape
                    j = k + 2
                    continue
                break
            buf.append(script[i:k + 1]); i = k + 1
        elif ch == "$" and (m := _DOLLAR_TAG.match(script, i)) and not _ident_char(script, i - 1):
            tag = m.group(0)
            k = script.find(tag, m.end())
            if k == -1:
                raise ValueError(f"unterminated dollar-quoted text {tag}")
            buf.append(script[i:k + len(tag)]); i = k + len(tag)
        elif ch == ";":
            _flush(buf, statements); buf = []; i += 1
        else:
            buf.append(ch); i += 1
    _flush(buf, statements)
    return statements


def _ident_char(text, idx):
    return idx >= 0 and (text[idx].isalnum() or text[idx] == "_")


def _flush(buf, statements):
    text = "".join(buf).strip()
    if _strip_comments(text).strip():
        statements.append(text)


def _strip_comments(text):
    return re.sub(r"--[^\n]*|/\*.*?\*/", "", text, flags=re.S)
