"""
Continuous Session Validator (Zero Trust Security) - base version

Idea: never trust a session just because it was valid at login.
On EVERY request, re-validate the token and re-score the risk of the
session based on context (IP, device, geo, idle time, request rate).
Decision: ALLOW, STEP_UP (re-authenticate / MFA) or TERMINATE.

Standard library only. Run:  python continuous_session_validator.py
"""

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum


class Decision(Enum):
    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    TERMINATE = "TERMINATE"


@dataclass
class RequestContext:
    ip: str
    user_agent: str
    country: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class Session:
    session_id: str
    user: str
    ip: str
    device_hash: str
    country: str
    created_at: float
    last_seen: float
    request_times: list = field(default_factory=list)
    risk: float = 0.0
    active: bool = True


class ContinuousSessionValidator:
    # Policy settings (tune per environment)
    IDLE_TIMEOUT = 15 * 60          # seconds without activity
    ABSOLUTE_TIMEOUT = 8 * 60 * 60  # max session lifetime
    RATE_WINDOW = 10                # seconds
    RATE_LIMIT = 20                 # max requests per window
    STEP_UP_THRESHOLD = 40
    TERMINATE_THRESHOLD = 80

    # Risk weights
    W_IP_CHANGE = 25
    W_DEVICE_CHANGE = 50
    W_COUNTRY_CHANGE = 40
    W_RATE_ANOMALY = 30

    def __init__(self):
        self._secret = secrets.token_bytes(32)
        self._sessions = {}
        self.audit_log = []

    # ---------- helpers ----------
    @staticmethod
    def _device_hash(user_agent: str) -> str:
        return hashlib.sha256(user_agent.encode()).hexdigest()

    def _sign(self, session_id: str) -> str:
        return hmac.new(self._secret, session_id.encode(), hashlib.sha256).hexdigest()

    def _log(self, session_id, event, detail=""):
        self.audit_log.append((time.strftime("%H:%M:%S"), session_id[:8], event, detail))

    # ---------- lifecycle ----------
    def create_session(self, user: str, ctx: RequestContext) -> str:
        """Issue a signed token: '<session_id>.<signature>'."""
        sid = secrets.token_urlsafe(16)
        now = ctx.timestamp
        self._sessions[sid] = Session(
            session_id=sid, user=user, ip=ctx.ip,
            device_hash=self._device_hash(ctx.user_agent),
            country=ctx.country, created_at=now, last_seen=now,
        )
        self._log(sid, "CREATED", f"user={user} ip={ctx.ip}")
        return f"{sid}.{self._sign(sid)}"

    def terminate(self, session_id: str, reason: str):
        s = self._sessions.get(session_id)
        if s:
            s.active = False
        self._log(session_id, "TERMINATED", reason)

    def reauthenticated(self, token: str, ctx: RequestContext):
        """Call after a successful step-up (MFA) to reset risk and re-bind context."""
        sid = token.split(".")[0]
        s = self._sessions.get(sid)
        if s and s.active:
            s.risk = 0.0
            s.ip, s.country = ctx.ip, ctx.country
            s.device_hash = self._device_hash(ctx.user_agent)
            self._log(sid, "STEP_UP_OK", "risk reset, context re-bound")

    # ---------- core check ----------
    def validate(self, token: str, ctx: RequestContext):
        """Validate one request. Returns (Decision, risk_score, reasons)."""
        try:
            sid, sig = token.split(".")
        except ValueError:
            return Decision.TERMINATE, 100.0, ["malformed token"]

        if not hmac.compare_digest(sig, self._sign(sid)):
            self._log(sid, "BAD_SIGNATURE")
            return Decision.TERMINATE, 100.0, ["invalid token signature"]

        s = self._sessions.get(sid)
        if not s or not s.active:
            return Decision.TERMINATE, 100.0, ["unknown or inactive session"]

        now = ctx.timestamp
        if now - s.last_seen > self.IDLE_TIMEOUT:
            self.terminate(sid, "idle timeout")
            return Decision.TERMINATE, 100.0, ["idle timeout"]
        if now - s.created_at > self.ABSOLUTE_TIMEOUT:
            self.terminate(sid, "absolute timeout")
            return Decision.TERMINATE, 100.0, ["absolute timeout"]

        # Contextual risk scoring
        score, reasons = 0.0, []
        if ctx.ip != s.ip:
            score += self.W_IP_CHANGE
            reasons.append(f"IP changed {s.ip} -> {ctx.ip}")
        if self._device_hash(ctx.user_agent) != s.device_hash:
            score += self.W_DEVICE_CHANGE
            reasons.append("device fingerprint changed")
        if ctx.country != s.country:
            score += self.W_COUNTRY_CHANGE
            reasons.append(f"country changed {s.country} -> {ctx.country}")

        s.request_times = [t for t in s.request_times if now - t <= self.RATE_WINDOW]
        s.request_times.append(now)
        if len(s.request_times) > self.RATE_LIMIT:
            score += self.W_RATE_ANOMALY
            reasons.append("abnormal request rate")

        s.risk = min(score, 100.0)
        s.last_seen = now

        if s.risk >= self.TERMINATE_THRESHOLD:
            self.terminate(sid, "; ".join(reasons))
            return Decision.TERMINATE, s.risk, reasons
        if s.risk >= self.STEP_UP_THRESHOLD:
            self._log(sid, "STEP_UP_REQUIRED", "; ".join(reasons))
            return Decision.STEP_UP, s.risk, reasons

        self._log(sid, "ALLOW", f"risk={s.risk}")
        return Decision.ALLOW, s.risk, reasons


# ---------- demo ----------
if __name__ == "__main__":
    v = ContinuousSessionValidator()
    laptop = "Mozilla/5.0 (Windows NT 10.0) Chrome/126"
    attacker = "curl/8.4"
    t0 = time.time()

    home = RequestContext("10.0.0.5", laptop, "US", t0)
    token = v.create_session("rohit", home)

    def show(label, ctx, tok=token):
        d, r, why = v.validate(tok, ctx)
        print(f"{label:<34} -> {d.value:<9} risk={r:<5} {why}")
        return d

    show("1. Normal request", RequestContext("10.0.0.5", laptop, "US", t0 + 5))
    show("2. IP changed (same device)", RequestContext("10.0.0.9", laptop, "US", t0 + 10))
    d = show("3. New device, same IP", RequestContext("10.0.0.9", attacker, "US", t0 + 15))
    if d == Decision.STEP_UP:
        v.reauthenticated(token, RequestContext("10.0.0.9", attacker, "US", t0 + 16))
    show("4. After MFA step-up", RequestContext("10.0.0.9", attacker, "US", t0 + 20))
    show("5. Country + device hijack", RequestContext("8.8.8.8", laptop, "RU", t0 + 25))
    show("6. Tampered token", RequestContext("10.0.0.5", laptop, "US", t0 + 30), token[:-4] + "0000")
    show("7. Idle timeout (20 min gap)", RequestContext("10.0.0.5", laptop, "US", t0 + 1300))

    print("\nAudit log:")
    for row in v.audit_log:
        print("  ", *row)
