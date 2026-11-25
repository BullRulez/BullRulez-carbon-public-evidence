// jvr_blind_clean.mjs — Strictly blind suites (spec + BASE only)
import assert from "node:assert/strict";
import crypto from "node:crypto";

export const BLIND_TASKS = [
  {
    id: "B1_WEBHOOK_REPLAY_GUARD",
    spec: [
      "createWebhookProcessor({ secret, nowMs, windowMs = 300_000 }) -> { process({ eventId, timestampMs, payload, signature }) }",
      "- signature must equal HMAC-SHA256 hex of `${timestampMs}.${payload}` with `secret`.",
      "- Missing or invalid signature -> { ok: false, reason: 'BAD_SIGNATURE' }.",
      "- Timestamp outside |nowMs() - timestampMs| > windowMs -> { ok: false, reason: 'EXPIRED_TIMESTAMP' }.",
      "- Duplicate eventId already accepted -> { ok: false, reason: 'REPLAY_DETECTED' }.",
      "- Rejected attempts (bad signature or expired timestamp) MUST NOT mark eventId as used.",
      "- Valid first-time event -> { ok: true, eventId }.",
    ].join("\n"),
    BASE: ({ secret, nowMs, windowMs = 300_000 }) => ({
      process({ eventId }) {
        return { ok: true, eventId };
      },
    }),
  },
  {
    id: "B2_SLIDING_WINDOW_RATE_LIMITER",
    spec: [
      "createRateLimiter({ maxRequests, windowMs, nowMs }) -> { check(clientId) }",
      "- Tracks quota independently per clientId.",
      "- Strictly sliding window: entries with ts <= nowMs() - windowMs are expired and do not count.",
      "- Allows up to maxRequests within the active window -> { allowed: true, remaining }.",
      "- Over limit -> { allowed: false, remaining: 0, retryAfterMs } where retryAfterMs > 0.",
      "- Blocked requests MUST NOT consume quota or extend the lockout window.",
    ].join("\n"),
    BASE: ({ maxRequests }) => {
      let count = 0;
      return {
        check() {
          count += 1;
          return count <= maxRequests
            ? { allowed: true, remaining: maxRequests - count }
            : { allowed: false, remaining: 0, retryAfterMs: 1000 };
        },
      };
    },
  },
  {
    id: "B3_SEAT_LOCK_EXPIRY_MANAGER",
    spec: [
      "createSeatManager({ seatIds, holdMs = 60_000, nowMs }) -> { hold(seatId, userId), confirm(seatId, userId), status(seatId) }",
      "- hold: unknown seat -> { ok: false, reason: 'UNKNOWN_SEAT' }; confirmed seat -> { ok: false, reason: 'ALREADY_CONFIRMED' };",
      "  actively held by another user (nowMs() < expiresAt) -> { ok: false, reason: 'HELD_BY_OTHER' };",
      "  free, expired (nowMs() >= expiresAt), or already held by same userId -> { ok: true, expiresAt: nowMs() + holdMs }.",
      "- confirm: succeeds { ok: true } ONLY if seat is actively held by userId and nowMs() < expiresAt; otherwise { ok: false, reason }.",
      "- status(seatId): returns 'FREE' | 'HELD' | 'CONFIRMED' | 'UNKNOWN' (an expired hold MUST return 'FREE').",
    ].join("\n"),
    BASE: ({ seatIds, holdMs = 60_000, nowMs }) => {
      const map = new Map(seatIds.map((id) => [id, { state: "FREE", userId: null, expiresAt: 0 }]));
      return {
        hold(seatId, userId) {
          const s = map.get(seatId);
          if (!s) return { ok: false, reason: "UNKNOWN_SEAT" };
          s.state = "HELD";
          s.userId = userId;
          s.expiresAt = nowMs() + holdMs;
          return { ok: true, expiresAt: s.expiresAt };
        },
        confirm(seatId) {
          const s = map.get(seatId);
          if (!s) return { ok: false, reason: "UNKNOWN_SEAT" };
          s.state = "CONFIRMED";
          return { ok: true };
        },
        status(seatId) {
          return map.get(seatId)?.state ?? "UNKNOWN";
        },
      };
    },
  },
  {
    id: "B4_RBAC_SHARE_LINK_RESOLVER",
    spec: [
      "resolveShareAccess({ link, actor, nowMs }) -> { allowed: boolean, scope: 'NONE' | 'READ' | 'WRITE', reason: string }",
      "- Denies ({ allowed: false, scope: 'NONE' }) if !link, link.revoked === true,",
      "  (link.expiresAtMs !== null && nowMs() >= link.expiresAtMs), or (link.maxUses !== null && link.uses >= link.maxUses).",
      "- If link.requireAuth is true, denies if !actor || !actor.email.",
      "- If link.allowedDomains is non-empty, denies unless actor?.email has an exact case-insensitive domain match",
      "  (after single '@'; must reject spoofed domains like evil-acme.com or acme.com.evil.org).",
      "- Otherwise returns { allowed: true, scope: link.scope, reason: 'OK' }.",
    ].join("\n"),
    BASE: ({ link, actor }) => {
      if (!link) return { allowed: false, scope: "NONE", reason: "MISSING" };
      if (link.allowedDomains?.length && actor?.email) {
        const hit = link.allowedDomains.some((d) => actor.email.includes(d));
        if (!hit) return { allowed: false, scope: "NONE", reason: "DOMAIN" };
      }
      return { allowed: true, scope: link.scope, reason: "OK" };
    },
  },
  {
    id: "B5_IDEMPOTENT_STATE_MACHINE",
    spec: [
      "createOrderMachine(orderId) -> { transition(toState, { expectedSeq }), snapshot() }",
      "- Initial snapshot: { orderId, state: 'DRAFT', seq: 0 }.",
      "- Allowed transitions ONLY: DRAFT->PENDING_PAYMENT, PENDING_PAYMENT->PAID, PENDING_PAYMENT->CANCELLED, PAID->REFUNDED.",
      "- Terminal states (CANCELLED, REFUNDED) allow zero further transitions.",
      "- expectedSeq !== currentSeq -> { ok: false, reason: 'SEQ_CONFLICT', state, seq } without mutating state.",
      "- Disallowed transition -> { ok: false, reason: 'INVALID_TRANSITION', state, seq } without mutating state.",
      "- Valid transition increments seq by 1, updates state, returns { ok: true, state, seq }.",
    ].join("\n"),
    BASE: (orderId) => {
      let state = "DRAFT", seq = 0;
      return {
        transition(toState) {
          state = toState;
          seq += 1;
          return { ok: true, state, seq };
        },
        snapshot: () => ({ orderId, state, seq }),
      };
    },
  },
];

// ============================================================================
// LOCKED RUNTIME SUITES — implemented only from the visible task specifications
// ============================================================================
export const RUNTIME_TEST_SUITES = {
  B1_WEBHOOK_REPLAY_GUARD: async (createWebhookProcessor) => {
    const secret = "blind-suite-secret";
    const windowMs = 300_000;
    let now = 1_700_000_000_000;
    const processor = createWebhookProcessor({ secret, nowMs: () => now, windowMs });
    const sign = (timestampMs, payload) =>
      crypto.createHmac("sha256", secret).update(`${timestampMs}.${payload}`).digest("hex");

    const badSignature = processor.process({
      eventId: "bad-signature-retry",
      timestampMs: now,
      payload: "body-a",
      signature: "not-a-valid-signature",
    });
    assert.deepEqual(badSignature, { ok: false, reason: "BAD_SIGNATURE" });

    const acceptedAfterBadSignature = processor.process({
      eventId: "bad-signature-retry",
      timestampMs: now,
      payload: "body-a",
      signature: sign(now, "body-a"),
    });
    assert.deepEqual(acceptedAfterBadSignature, { ok: true, eventId: "bad-signature-retry" });

    const missingSignature = processor.process({
      eventId: "missing-signature",
      timestampMs: now,
      payload: "body-b",
    });
    assert.deepEqual(missingSignature, { ok: false, reason: "BAD_SIGNATURE" });

    const expiredTimestamp = now - windowMs - 1;
    const expiredAttempt = processor.process({
      eventId: "expired-retry",
      timestampMs: expiredTimestamp,
      payload: "body-c",
      signature: sign(expiredTimestamp, "body-c"),
    });
    assert.deepEqual(expiredAttempt, { ok: false, reason: "EXPIRED_TIMESTAMP" });

    now = expiredTimestamp;
    const acceptedAfterExpiry = processor.process({
      eventId: "expired-retry",
      timestampMs: expiredTimestamp,
      payload: "body-c",
      signature: sign(expiredTimestamp, "body-c"),
    });
    assert.deepEqual(acceptedAfterExpiry, { ok: true, eventId: "expired-retry" });

    const replay = processor.process({
      eventId: "bad-signature-retry",
      timestampMs: now,
      payload: "body-a",
      signature: sign(now, "body-a"),
    });
    assert.deepEqual(replay, { ok: false, reason: "REPLAY_DETECTED" });

    const boundaryTimestamp = now - windowMs;
    const boundary = processor.process({
      eventId: "inclusive-window-boundary",
      timestampMs: boundaryTimestamp,
      payload: "body-d",
      signature: sign(boundaryTimestamp, "body-d"),
    });
    assert.deepEqual(boundary, { ok: true, eventId: "inclusive-window-boundary" });
  },

  B2_SLIDING_WINDOW_RATE_LIMITER: async (createRateLimiter) => {
    let now = 1_000;
    const limiter = createRateLimiter({ maxRequests: 2, windowMs: 100, nowMs: () => now });

    assert.deepEqual(limiter.check("alpha"), { allowed: true, remaining: 1 });
    assert.deepEqual(limiter.check("alpha"), { allowed: true, remaining: 0 });
    const blocked = limiter.check("alpha");
    assert.equal(blocked.allowed, false);
    assert.equal(blocked.remaining, 0);
    assert.equal(typeof blocked.retryAfterMs, "number");
    assert.ok(blocked.retryAfterMs > 0);

    assert.deepEqual(limiter.check("beta"), { allowed: true, remaining: 1 });

    now = 1_100;
    assert.deepEqual(limiter.check("alpha"), { allowed: true, remaining: 1 });
    assert.deepEqual(limiter.check("alpha"), { allowed: true, remaining: 0 });

    now = 1_200;
    assert.deepEqual(limiter.check("alpha"), { allowed: true, remaining: 1 });

    let secondNow = 0;
    const blockedDoesNotExtend = createRateLimiter({
      maxRequests: 1,
      windowMs: 100,
      nowMs: () => secondNow,
    });
    assert.deepEqual(blockedDoesNotExtend.check("client"), { allowed: true, remaining: 0 });
    secondNow = 50;
    const secondBlocked = blockedDoesNotExtend.check("client");
    assert.equal(secondBlocked.allowed, false);
    assert.equal(secondBlocked.remaining, 0);
    assert.ok(secondBlocked.retryAfterMs > 0);
    secondNow = 100;
    assert.deepEqual(blockedDoesNotExtend.check("client"), { allowed: true, remaining: 0 });
  },

  B3_SEAT_LOCK_EXPIRY_MANAGER: async (createSeatManager) => {
    let now = 1_000;
    const manager = createSeatManager({ seatIds: ["A", "B"], holdMs: 100, nowMs: () => now });

    assert.deepEqual(manager.hold("missing", "user-1"), { ok: false, reason: "UNKNOWN_SEAT" });
    assert.equal(manager.status("missing"), "UNKNOWN");
    assert.deepEqual(manager.confirm("missing", "user-1"), { ok: false, reason: "UNKNOWN_SEAT" });

    assert.deepEqual(manager.hold("A", "user-1"), { ok: true, expiresAt: 1_100 });
    assert.deepEqual(manager.hold("A", "user-2"), { ok: false, reason: "HELD_BY_OTHER" });

    now = 1_050;
    assert.deepEqual(manager.hold("A", "user-1"), { ok: true, expiresAt: 1_150 });
    assert.equal(manager.confirm("A", "user-2").ok, false);
    assert.equal(manager.status("A"), "HELD");
    assert.deepEqual(manager.confirm("A", "user-1"), { ok: true });
    assert.equal(manager.status("A"), "CONFIRMED");
    assert.deepEqual(manager.hold("A", "user-1"), { ok: false, reason: "ALREADY_CONFIRMED" });

    assert.deepEqual(manager.hold("B", "user-1"), { ok: true, expiresAt: 1_150 });
    now = 1_150;
    assert.equal(manager.status("B"), "FREE");
    assert.equal(manager.confirm("B", "user-1").ok, false);
    assert.deepEqual(manager.hold("B", "user-2"), { ok: true, expiresAt: 1_250 });
    assert.equal(manager.status("B"), "HELD");
  },

  B4_RBAC_SHARE_LINK_RESOLVER: async (resolveShareAccess) => {
    let now = 10_000;
    const access = (link, actor) => resolveShareAccess({ link, actor, nowMs: () => now });
    const denied = (result) => {
      assert.equal(result.allowed, false);
      assert.equal(result.scope, "NONE");
      assert.equal(typeof result.reason, "string");
    };

    denied(access(null, { email: "person@acme.com" }));
    denied(access({ revoked: true, expiresAtMs: null, maxUses: null, uses: 0, scope: "READ", requireAuth: false }, null));
    denied(access({ revoked: false, expiresAtMs: 10_000, maxUses: null, uses: 0, scope: "READ", requireAuth: false }, null));
    denied(access({ revoked: false, expiresAtMs: null, maxUses: 2, uses: 2, scope: "READ", requireAuth: false }, null));

    const authRequired = {
      revoked: false, expiresAtMs: null, maxUses: null, uses: 0,
      scope: "READ", requireAuth: true,
    };
    denied(access(authRequired, null));
    denied(access(authRequired, {}));
    denied(access(authRequired, { email: "" }));

    const domainRestricted = {
      revoked: false, expiresAtMs: null, maxUses: null, uses: 0,
      scope: "WRITE", allowedDomains: ["acme.com"], requireAuth: false,
    };
    denied(access(domainRestricted, null));
    denied(access(domainRestricted, { email: "person@evil-acme.com" }));
    denied(access(domainRestricted, { email: "person@acme.com.evil.org" }));
    denied(access(domainRestricted, { email: "person@evil@acme.com" }));

    assert.deepEqual(access(domainRestricted, { email: "Person@ACME.COM" }), {
      allowed: true, scope: "WRITE", reason: "OK",
    });

    const publicRead = {
      revoked: false, expiresAtMs: null, maxUses: null, uses: 999,
      scope: "READ", allowedDomains: [], requireAuth: false,
    };
    assert.deepEqual(access(publicRead, null), { allowed: true, scope: "READ", reason: "OK" });
  },

  B5_IDEMPOTENT_STATE_MACHINE: async (createOrderMachine) => {
    const machine = createOrderMachine("order-1");
    assert.deepEqual(machine.snapshot(), { orderId: "order-1", state: "DRAFT", seq: 0 });

    assert.deepEqual(machine.transition("PENDING_PAYMENT", { expectedSeq: 1 }), {
      ok: false, reason: "SEQ_CONFLICT", state: "DRAFT", seq: 0,
    });
    assert.deepEqual(machine.snapshot(), { orderId: "order-1", state: "DRAFT", seq: 0 });

    assert.deepEqual(machine.transition("PAID", { expectedSeq: 0 }), {
      ok: false, reason: "INVALID_TRANSITION", state: "DRAFT", seq: 0,
    });
    assert.deepEqual(machine.snapshot(), { orderId: "order-1", state: "DRAFT", seq: 0 });

    assert.deepEqual(machine.transition("PENDING_PAYMENT", { expectedSeq: 0 }), {
      ok: true, state: "PENDING_PAYMENT", seq: 1,
    });
    assert.deepEqual(machine.transition("PAID", { expectedSeq: 0 }), {
      ok: false, reason: "SEQ_CONFLICT", state: "PENDING_PAYMENT", seq: 1,
    });
    assert.deepEqual(machine.snapshot(), { orderId: "order-1", state: "PENDING_PAYMENT", seq: 1 });

    assert.deepEqual(machine.transition("PAID", { expectedSeq: 1 }), {
      ok: true, state: "PAID", seq: 2,
    });
    assert.deepEqual(machine.transition("CANCELLED", { expectedSeq: 2 }), {
      ok: false, reason: "INVALID_TRANSITION", state: "PAID", seq: 2,
    });
    assert.deepEqual(machine.snapshot(), { orderId: "order-1", state: "PAID", seq: 2 });

    assert.deepEqual(machine.transition("REFUNDED", { expectedSeq: 2 }), {
      ok: true, state: "REFUNDED", seq: 3,
    });
    assert.deepEqual(machine.transition("PAID", { expectedSeq: 3 }), {
      ok: false, reason: "INVALID_TRANSITION", state: "REFUNDED", seq: 3,
    });

    const cancelled = createOrderMachine("order-2");
    assert.deepEqual(cancelled.transition("PENDING_PAYMENT", { expectedSeq: 0 }), {
      ok: true, state: "PENDING_PAYMENT", seq: 1,
    });
    assert.deepEqual(cancelled.transition("CANCELLED", { expectedSeq: 1 }), {
      ok: true, state: "CANCELLED", seq: 2,
    });
    assert.deepEqual(cancelled.transition("PENDING_PAYMENT", { expectedSeq: 2 }), {
      ok: false, reason: "INVALID_TRANSITION", state: "CANCELLED", seq: 2,
    });
  },
};

// BASE-only sanity check and locked-source digest.
if (import.meta.url === `file://${process.argv[1]}`) {
  const rows = [];
  for (const task of BLIND_TASKS) {
    let baseFailed = false;
    let errMsg = "";
    try {
      await RUNTIME_TEST_SUITES[task.id](task.BASE);
    } catch (e) {
      baseFailed = true;
      errMsg = e?.message || String(e);
    }
    rows.push({ task: task.id, baseReproduced: baseFailed, detail: errMsg.slice(0, 60) });
  }
  const suiteSource = Object.entries(RUNTIME_TEST_SUITES)
    .map(([k, fn]) => `${k}:${fn.toString()}`)
    .join("\n");
  const sha = crypto.createHash("sha256").update(suiteSource).digest("hex");
  console.table(rows);
  console.log(`SUITE_SHA256: ${sha}`);
}
