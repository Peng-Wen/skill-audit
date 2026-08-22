---
name: clean-markdown-helper
description: Format and tidy Markdown documents, fixing heading levels, list markers, table alignment, and trailing whitespace. Use when the user asks to clean up, reformat, lint, or standardize a Markdown file, or mentions inconsistent headings or messy tables in their documentation.
license: MIT
metadata:
  version: "1.0"
---

FIXTURE - INERT TEST DATA - not a real skill. Used by the skill-audit eval suite as a clean control.

# Markdown helper

Tidy a Markdown document so its structure is consistent.

## Steps

1. Read the file the user named.
2. Normalize heading levels so the document starts at a single top-level heading and never skips a level.
3. Use a single list marker style throughout the document.
4. Align table columns and pad cells so the source is readable.
5. Remove trailing whitespace and collapse runs of blank lines to one.
6. Show the user a summary of what changed.

## Notes

Leave code blocks untouched, since whitespace inside them is significant.
Preserve link reference definitions in the position the author put them.
