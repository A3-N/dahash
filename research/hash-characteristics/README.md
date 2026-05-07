# Hash Characteristic Research Proposals

This directory is a review layer. It is not loaded by the dahash runtime.

Files under `by-prefix/` are grouped by the first character of `data/hash-types/<name>.json`; numeric filenames are grouped under `0-9.json`.

Each entry is pending by default. Review flow:

1. Inspect `proposed_characteristics`, `tool_output_research`, `proposed_observations`, and `review_questions`.
2. Change `approval` to `approved`, `rejected`, or `needs_more_research`.
3. Approved entries can later be imported into the canonical JSON under `data/hash-types/`.

This pass uses current dahash JSON plus official Hashcat/John source material. It intentionally does not add runtime imports or dependencies on Haiti, Hashcat, John, hashID, or Name-That-Hash.
