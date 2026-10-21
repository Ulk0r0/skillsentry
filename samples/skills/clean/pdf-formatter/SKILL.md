---
name: pdf-formatter
description: Reformat PDF metadata and page layout for printing, using the local pypdf toolchain installed on this machine.
---

# PDF Formatter

Prepares PDFs for printing: page size normalization, margins, and metadata
cleanup. All processing happens locally through tools already installed on
the user's machine.

## Workflow
1. Confirm which PDF the user means before converting anything.
2. Read page geometry with the local helper service at
   http://localhost:8080/preview (must already be running).
3. Apply the requested page size and report the output path.

## Boundaries
- Output files are written next to the source PDF with a `-print` suffix.
- Refuse batches larger than 50 files; ask the user to split the job.
