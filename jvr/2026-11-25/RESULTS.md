# Results and verification record

**Run date:** 2026-11-25  
**Runtime:** Node.js, executed locally in the ChatGPT task environment  
**Input boundary:** Visible specifications and supplied BASE implementations only  
**Hidden candidates:** GOLD/M1/M2/M3 were not supplied or evaluated

## Locked suite results

| Suite | Supplied BASE | Spec-derived reference |
|---|---:|---:|
| B1_WEBHOOK_REPLAY_GUARD | FAIL (expected) | PASS |
| B2_SLIDING_WINDOW_RATE_LIMITER | FAIL (expected) | PASS |
| B3_SEAT_LOCK_EXPIRY_MANAGER | FAIL (expected) | PASS |
| B4_RBAC_SHARE_LINK_RESOLVER | FAIL (expected) | PASS |
| B5_IDEMPOTENT_STATE_MACHINE | FAIL (expected) | PASS |
| **Total** | **5/5 failures reproduced** | **5/5 passes** |

The BASE column is a negative control: each supplied implementation is expected to fail its corresponding specification tests. The reference column is a positive control: the suites pass against visible, spec-derived implementations. The positive controls are included so the verification can be repeated; they are not presented as hidden or independently sourced gold solutions.

## Integrity values

**Locked suite source SHA-256** (calculated from the ordered RUNTIME_TEST_SUITES function source using the harness's prescribed serialization):

    5943052940a1f57ea85d39dd1b7a46fa8c987e7b35f92e5eca4705fa2a19214b

**Published harness file SHA-256:**

    0672482cff1fed9ec9b4fc321c565a7347057e73f542c6d550af1e17757271f3

## Interpretation and exclusions

This run demonstrates that the five test suites reproduce the defects in the five supplied BASE implementations and accept separate implementations conforming to the visible specifications. It is evidence of blind test-suite construction and execution, not proof that a production codebase has been repaired.

No hidden GOLD/M1/M2/M3 candidate was tested. No competitor or industry benchmark was run. The claimed industry “9%” figure was not provided with a source or methodology and is not validated by this evidence. No deployment, customer outcome, revenue, or production readiness claim is made.
