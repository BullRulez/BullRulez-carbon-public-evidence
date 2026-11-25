import assert from "node:assert/strict";
import crypto from "node:crypto";
import { BLIND_TASKS, RUNTIME_TEST_SUITES } from "./jvr_blind_clean.mjs";
import { REFERENCE_IMPLEMENTATIONS } from "./reference_implementations.mjs";

const results = [];
for (const task of BLIND_TASKS) {
  let baseError;
  try {
    await RUNTIME_TEST_SUITES[task.id](task.BASE);
  } catch (error) {
    baseError = error;
  }
  assert.equal(baseError?.code, "ERR_ASSERTION", task.id + " must fail on BASE via an assertion");
  await RUNTIME_TEST_SUITES[task.id](REFERENCE_IMPLEMENTATIONS[task.id]);
  results.push({ suite: task.id, base: "FAIL (expected)", reference: "PASS" });
}

const suiteSource = Object.entries(RUNTIME_TEST_SUITES)
  .map(([key, fn]) => key + ":" + fn.toString())
  .join("\n");
const suiteSha = crypto.createHash("sha256").update(suiteSource).digest("hex");
assert.equal(suiteSha, "5943052940a1f57ea85d39dd1b7a46fa8c987e7b35f92e5eca4705fa2a19214b",
  "Locked suite digest changed");

console.table(results);
console.log("BASE_REPRODUCED: 5/5");
console.log("REFERENCE_PASSES: 5/5");
console.log("SUITE_SHA256: " + suiteSha);
