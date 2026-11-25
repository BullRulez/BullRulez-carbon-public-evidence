# JVR blind-suite evidence — 25 November 2026

## Published artifacts

- jvr/2026-11-25/jvr_blind_clean.mjs — locked test suites and supplied BASE fixtures.
- jvr/2026-11-25/reference_implementations.mjs — transparent, spec-derived positive-control implementations; not hidden GOLD implementations.
- jvr/2026-11-25/verify.mjs — one-command verification of BASE failures, reference passes, and the locked suite digest.
- jvr/2026-11-25/RESULTS.md — scope, results, and limitations.

## What this evidence supports

A fresh ChatGPT Free-plan conversation authored five blind JavaScript test suites using only the five visible specifications and their supplied BASE implementations. No active AMX worker or custom AMX runtime was used for the test-authoring step. The included Node.js verification command checks that all five suites fail against the supplied BASE fixtures and pass against separate reference implementations written from the visible specifications.

Run from the repository root:

    node jvr/2026-11-25/verify.mjs

Expected result: 5/5 BASE failures reproduced, 5/5 spec-reference passes, and the locked suite digest printed.

## Limits

This is a five-task blind test-authoring demonstration. It does not evaluate hidden GOLD, M1, M2, or M3 implementations; does not demonstrate production fixes or deployment; and does not establish an industry-wide success rate or substantiate a separate “9%” benchmark. Reference implementations are positive controls authored transparently from the visible specifications, not independent ground-truth vendor submissions.
