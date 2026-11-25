import crypto from "node:crypto";

export const REFERENCE_IMPLEMENTATIONS = {
  B1_WEBHOOK_REPLAY_GUARD: ({ secret, nowMs, windowMs = 300_000 }) => {
    const accepted = new Set();
    return {
      process({ eventId, timestampMs, payload, signature }) {
        const expected = crypto.createHmac("sha256", secret)
          .update(String(timestampMs) + "." + String(payload)).digest("hex");
        if (!signature || signature !== expected) return { ok: false, reason: "BAD_SIGNATURE" };
        if (Math.abs(nowMs() - timestampMs) > windowMs) return { ok: false, reason: "EXPIRED_TIMESTAMP" };
        if (accepted.has(eventId)) return { ok: false, reason: "REPLAY_DETECTED" };
        accepted.add(eventId);
        return { ok: true, eventId };
      },
    };
  },
  B2_SLIDING_WINDOW_RATE_LIMITER: ({ maxRequests, windowMs, nowMs }) => {
    const events = new Map();
    return {
      check(clientId) {
        const now = nowMs();
        const active = (events.get(clientId) ?? []).filter(ts => ts > now - windowMs);
        if (active.length >= maxRequests) {
          events.set(clientId, active);
          return { allowed: false, remaining: 0, retryAfterMs: Math.max(1, active[0] + windowMs - now) };
        }
        active.push(now);
        events.set(clientId, active);
        return { allowed: true, remaining: maxRequests - active.length };
      },
    };
  },
  B3_SEAT_LOCK_EXPIRY_MANAGER: ({ seatIds, holdMs = 60_000, nowMs }) => {
    const seats = new Map(seatIds.map(id => [id, { state: "FREE", userId: null, expiresAt: 0 }]));
    return {
      hold(seatId, userId) {
        const seat = seats.get(seatId);
        if (!seat) return { ok: false, reason: "UNKNOWN_SEAT" };
        if (seat.state === "CONFIRMED") return { ok: false, reason: "ALREADY_CONFIRMED" };
        if (seat.state === "HELD" && nowMs() < seat.expiresAt && seat.userId !== userId) {
          return { ok: false, reason: "HELD_BY_OTHER" };
        }
        seat.state = "HELD";
        seat.userId = userId;
        seat.expiresAt = nowMs() + holdMs;
        return { ok: true, expiresAt: seat.expiresAt };
      },
      confirm(seatId, userId) {
        const seat = seats.get(seatId);
        if (!seat) return { ok: false, reason: "UNKNOWN_SEAT" };
        if (seat.state !== "HELD" || seat.userId !== userId || !(nowMs() < seat.expiresAt)) {
          return { ok: false, reason: "NOT_ACTIVE_HOLD" };
        }
        seat.state = "CONFIRMED";
        return { ok: true };
      },
      status(seatId) {
        const seat = seats.get(seatId);
        if (!seat) return "UNKNOWN";
        if (seat.state === "HELD" && nowMs() >= seat.expiresAt) return "FREE";
        return seat.state;
      },
    };
  },
  B4_RBAC_SHARE_LINK_RESOLVER: ({ link, actor, nowMs }) => {
    const deny = reason => ({ allowed: false, scope: "NONE", reason });
    if (!link) return deny("MISSING");
    if (link.revoked === true) return deny("REVOKED");
    if (link.expiresAtMs !== null && nowMs() >= link.expiresAtMs) return deny("EXPIRED");
    if (link.maxUses !== null && link.uses >= link.maxUses) return deny("MAX_USES");
    if (link.requireAuth && (!actor || !actor.email)) return deny("AUTH_REQUIRED");
    if (Array.isArray(link.allowedDomains) && link.allowedDomains.length > 0) {
      const email = actor?.email;
      if (typeof email !== "string") return deny("DOMAIN");
      const parts = email.split("@");
      if (parts.length !== 2 || !parts[0] || !parts[1]) return deny("DOMAIN");
      const domain = parts[1].toLowerCase();
      if (!link.allowedDomains.some(d => String(d).toLowerCase() === domain)) return deny("DOMAIN");
    }
    return { allowed: true, scope: link.scope, reason: "OK" };
  },
  B5_IDEMPOTENT_STATE_MACHINE: orderId => {
    let state = "DRAFT";
    let seq = 0;
    const allowed = {
      DRAFT: new Set(["PENDING_PAYMENT"]),
      PENDING_PAYMENT: new Set(["PAID", "CANCELLED"]),
      PAID: new Set(["REFUNDED"]),
      CANCELLED: new Set(),
      REFUNDED: new Set(),
    };
    return {
      transition(toState, { expectedSeq } = {}) {
        if (expectedSeq !== seq) return { ok: false, reason: "SEQ_CONFLICT", state, seq };
        if (!allowed[state]?.has(toState)) return { ok: false, reason: "INVALID_TRANSITION", state, seq };
        state = toState;
        seq += 1;
        return { ok: true, state, seq };
      },
      snapshot: () => ({ orderId, state, seq }),
    };
  },
};
