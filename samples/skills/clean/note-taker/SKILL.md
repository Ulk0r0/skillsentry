---
name: note-taker
description: Create, organize and search personal notes stored locally in plain markdown files.
---

# Note Taker

Helps the user capture and organize short notes as markdown files in the
current workspace.

## When to use
- The user asks to remember something, jot down an idea, or keep a list.
- The user wants to find a note they saved earlier.

## How to use
1. Ask the user where notes live if no folder was configured (default: `./notes`).
2. One note per file, filename derived from the first heading.
3. When listing notes, show title and last-modified date only.

## Boundaries
- Never touch files outside the configured notes folder.
- If a save fails, tell the user and keep their text intact.
