"""Tests for REGISTER behavior: granted-expiry parsing, refresh scheduling,
423 Min-Expires handling, and Call-ID/CSeq sequencing.

No network I/O: UserAgent._send_and_wait is replaced with a scripted stub,
and the refresh loop's clock/sleep go through the opensip.ua._monotonic /
opensip.ua._sleep seams.
"""

import asyncio
import logging

import pytest

import opensip.ua as ua_mod
from opensip.exceptions import AuthenticationError, RegistrationError
from opensip.headers import URI
from opensip.message import Headers, SIPRequest, SIPResponse
from opensip.ua import (
    Account,
    UserAgent,
    _granted_expires,
    _refresh_delay,
    _refresh_failure_delay,
    _RegisterResult,
)

LOCAL = URI(user="alice", host="client.example.com", port=5061)
MATCH = "<sip:alice@client.example.com:5061>"

CHALLENGE = ("WWW-Authenticate", 'Digest realm="test", nonce="abc"')


def _resp(status: int = 200, reason: str = "OK",
          headers: list[tuple[str, str]] | None = None) -> SIPResponse:
    return SIPResponse(headers=Headers(headers or []),
                       status_code=status, reason=reason)


def _granted(requested: int = 600, *headers: tuple[str, str],
             local: URI = LOCAL) -> int:
    return _granted_expires(_resp(headers=list(headers)), local, requested)


# ---------------------------------------------------------------------------
# Granted-expiry parsing: locating the expires parameter
# ---------------------------------------------------------------------------

def test_angle_bracket_contact_expires():
    assert _granted(600, ("Contact", f"{MATCH};expires=45")) == 45


def test_bare_contact_expires():
    # Bare form: the parser flattens header params onto the URI; they must
    # still be read as the binding expiry (RFC 3261 §20.10).
    assert _granted(600, ("Contact", "sip:alice@client.example.com:5061;expires=45")) == 45


def test_uri_param_and_header_param_coexist():
    contact = "<sip:alice@client.example.com:5061;transport=udp>;expires=45"
    assert _granted(600, ("Contact", contact)) == 45


def test_expires_uri_param_inside_brackets_ignored():
    contact = "<sip:alice@client.example.com:5061;expires=9999>;q=0.5;expires=45"
    assert _granted(600, ("Contact", contact)) == 45
    # Without a header param, the bracketed URI param must not be used.
    contact = "<sip:alice@client.example.com:5061;expires=9999>"
    assert _granted(600, ("Contact", contact), ("Expires", "100")) == 100


def test_expires_param_name_case_insensitive():
    assert _granted(600, ("Contact", f"{MATCH};EXPIRES=45")) == 45


# ---------------------------------------------------------------------------
# Granted-expiry parsing: matching
# ---------------------------------------------------------------------------

def test_only_matching_binding_used_across_headers():
    assert _granted(
        600,
        ("Contact", "<sip:other@example.com>;expires=99"),
        ("Contact", f"{MATCH};expires=45"),
    ) == 45


def test_only_matching_binding_used_in_comma_list():
    contacts = f"<sip:other@example.com>;expires=99, {MATCH};expires=45"
    assert _granted(600, ("Contact", contacts)) == 45


def test_display_name_with_comma_does_not_break_splitting():
    contacts = f'"Doe, Jane" {MATCH};expires=45, <sip:other@example.com>;expires=99'
    assert _granted(600, ("Contact", contacts)) == 45


def test_scheme_and_host_case_insensitive():
    assert _granted(600, ("Contact", "<SIP:alice@CLIENT.EXAMPLE.COM:5061>;expires=45")) == 45


def test_user_case_sensitive_no_match():
    local = URI(user="Alice", host="client.example.com", port=5061)
    assert _granted(
        600,
        ("Contact", "<sip:alice@client.example.com:5061>;expires=45"),
        ("Expires", "60"),
        local=local,
    ) == 60


def test_absent_port_matches_default_5060():
    local = URI(user="alice", host="client.example.com", port=5060)
    assert _granted(
        600, ("Contact", "<sip:alice@client.example.com>;expires=45"), local=local,
    ) == 45


def test_ipv6_literal_match():
    local = URI(user="alice", host="2001:db8::1", port=5060)
    assert _granted(
        600, ("Contact", "<sip:alice@[2001:DB8::1]:5060>;expires=60"), local=local,
    ) == 60


def test_first_matching_binding_wins():
    assert _granted(
        600,
        ("Contact", f"{MATCH};expires=45, {MATCH};expires=99"),
    ) == 45


# ---------------------------------------------------------------------------
# Granted-expiry parsing: precedence and fallbacks
# ---------------------------------------------------------------------------

def test_contact_expires_overrides_expires_header():
    assert _granted(600, ("Contact", f"{MATCH};expires=45"), ("Expires", "100")) == 45


def test_expires_header_used_when_contact_has_no_expires():
    assert _granted(600, ("Contact", MATCH), ("Expires", "60")) == 60


def test_no_contacts_expires_header_used():
    assert _granted(600, ("Expires", "60")) == 60


def test_multiple_expires_headers_first_wins():
    assert _granted(600, ("Expires", "60"), ("Expires", "99")) == 60


def test_unusable_first_expires_header_falls_through():
    # Later duplicates are not scanned.
    assert _granted(600, ("Expires", "bogus"), ("Expires", "99")) == 600


def test_requested_used_when_response_has_nothing():
    assert _granted(600) == 600


def test_nonnumeric_and_negative_values_fall_through():
    # Malformed / negative values are tolerated (NAT-rewritten Contacts etc.):
    # they fall through, they do not deny.
    assert _granted(600, ("Contact", f"{MATCH};expires=abc"), ("Expires", "60")) == 60
    assert _granted(600, ("Contact", f"{MATCH};expires=-1"), ("Expires", "60")) == 60
    assert _granted(600, ("Expires", "bogus")) == 600
    assert _granted(600, ("Expires", "-5")) == 600


def test_registration_error_exported_at_top_level():
    # Callers catch registration denial without importing opensip.exceptions.
    import opensip
    assert opensip.RegistrationError is RegistrationError
    assert "RegistrationError" in opensip.__all__


# ---------------------------------------------------------------------------
# Fix 1: an affirmative expires=0 is a denial, not a fall-through
# ---------------------------------------------------------------------------

def test_matching_contact_expires_zero_raises():
    # Even with a usable Expires header present, a matching Contact binding
    # granting 0 is an affirmative denial.
    with pytest.raises(RegistrationError):
        _granted(600, ("Contact", f"{MATCH};expires=0"), ("Expires", "60"))


def test_expires_header_zero_raises_when_no_usable_contact():
    with pytest.raises(RegistrationError):
        _granted(600, ("Contact", MATCH), ("Expires", "0"))


def test_expires_header_zero_raises_with_no_contacts():
    with pytest.raises(RegistrationError):
        _granted(600, ("Expires", "0"))


def test_unregister_expires_zero_does_not_raise():
    # requested == 0 (an unregister): Expires: 0 / Contact expires=0 is the
    # expected success, not a denial.
    assert _granted(0, ("Contact", MATCH), ("Expires", "0")) == 0
    assert _granted(0, ("Contact", f"{MATCH};expires=0")) == 0
    assert _granted(0) == 0


def test_final_fallback_to_requested_logs_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="opensip.ua"):
        assert _granted(600) == 600
    assert any(r.levelno == logging.WARNING for r in caplog.records), \
        "the we're-guessing fall-back-to-requested path must log at WARNING"


# ---------------------------------------------------------------------------
# Fix 3: clamp a granted expiry that exceeds the requested value
# ---------------------------------------------------------------------------

def test_contact_grant_above_requested_is_clamped(caplog):
    with caplog.at_level(logging.WARNING, logger="opensip.ua"):
        assert _granted(60, ("Contact", f"{MATCH};expires=120")) == 60
    assert any("clamp" in r.getMessage().lower() for r in caplog.records)


def test_expires_header_grant_above_requested_is_clamped():
    assert _granted(60, ("Expires", "120")) == 60


def test_malformed_and_wildcard_contacts_skipped():
    assert _granted(
        600,
        ("Contact", "*"),
        ("Contact", "  *  "),
        ("Contact", "not-a-uri"),
        ("Contact", f"{MATCH};expires=45"),
    ) == 45


# ---------------------------------------------------------------------------
# Delay helpers
# ---------------------------------------------------------------------------

def test_refresh_delay_typical_grants():
    assert _refresh_delay(600) == 540.0
    assert _refresh_delay(10) == 9.0


def test_refresh_delay_tiny_grants_stay_before_expiry():
    assert _refresh_delay(1) == 0.5
    assert _refresh_delay(2) == 1.0
    for granted in (1, 2, 3, 5):
        assert _refresh_delay(granted) < granted


def test_refresh_failure_delay_clamps():
    assert _refresh_failure_delay(360) == 30.0
    assert _refresh_failure_delay(1.0) == 0.5
    assert _refresh_failure_delay(0.4) == 0.25
    assert _refresh_failure_delay(0.0) == 5.0
    assert _refresh_failure_delay(-5.0) == 5.0


# ---------------------------------------------------------------------------
# _send_register flows (scripted transport)
# ---------------------------------------------------------------------------

class _Script:
    """Replaces UserAgent._send_and_wait with scripted responses."""

    def __init__(self, *items):
        self.items = list(items)
        self.requests: list[SIPRequest] = []

    async def send_and_wait(self, req, dest, call_id, cseq_num, timeout=32.0):
        self.requests.append(req)
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def cseqs(self) -> list[int]:
        return [req.cseq[0] for req in self.requests]

    def call_ids(self) -> list[str]:
        return [req.call_id for req in self.requests]

    def expires(self) -> list[str]:
        return [req.headers.get("Expires") for req in self.requests]


def _make_ua(*items) -> tuple[UserAgent, Account, _Script]:
    ua = UserAgent(local_addr=("127.0.0.1", 5061))
    account = Account(username="alice", domain="example.com", password="pw",
                      server=("127.0.0.1", 5060))
    script = _Script(*items)
    ua._send_and_wait = script.send_and_wait
    return ua, account, script


def _ok(expires: int = 60) -> SIPResponse:
    return _resp(200, headers=[
        ("Contact", f"<sip:alice@127.0.0.1:5061>;expires={expires}")])


async def _drop_refresh_task(account: Account) -> None:
    task = account._register_task
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        account._register_task = None


async def test_call_id_generated_lazily_and_reused():
    ua, account, script = _make_ua(_ok(), _ok())
    assert account._register_call_id is None
    await ua.register(account)
    first = account._register_call_id
    assert first is not None
    await ua.register(account)
    assert account._register_call_id == first
    assert script.call_ids() == [first, first]
    assert script.cseqs() == [1, 2]
    await _drop_refresh_task(account)


async def test_auth_retry_keeps_call_id_increments_cseq():
    ua, account, script = _make_ua(_resp(401, "Unauthorized", [CHALLENGE]), _ok())
    await ua.register(account)
    assert len(script.requests) == 2
    assert script.call_ids()[0] == script.call_ids()[1]
    assert script.cseqs() == [1, 2]
    assert script.requests[1].headers.get("Authorization")
    await _drop_refresh_task(account)


async def test_full_401_423_401_200_sequence():
    ua, account, script = _make_ua(
        _resp(401, "Unauthorized", [CHALLENGE]),
        _resp(423, "Interval Too Brief", [("Min-Expires", "120")]),
        _resp(401, "Unauthorized", [CHALLENGE]),
        _ok(120),
    )
    await ua.register(account, expires=60)
    assert script.cseqs() == [1, 2, 3, 4]
    assert len(set(script.call_ids())) == 1
    assert script.expires() == ["60", "60", "120", "120"]
    # The raised value must not rewrite account configuration.
    assert account.expires == 600
    await _drop_refresh_task(account)


async def test_repeat_423_raises():
    ua, account, script = _make_ua(
        _resp(423, "Interval Too Brief", [("Min-Expires", "120")]),
        _resp(423, "Interval Too Brief", [("Min-Expires", "180")]),
    )
    with pytest.raises(AuthenticationError):
        await ua.register(account, expires=60)
    assert len(script.requests) == 2
    assert account._register_task is None


async def test_423_without_min_expires_raises():
    ua, account, script = _make_ua(_resp(423, "Interval Too Brief"))
    with pytest.raises(AuthenticationError):
        await ua.register(account, expires=60)
    assert len(script.requests) == 1


async def test_423_min_expires_not_above_request_raises():
    ua, account, script = _make_ua(
        _resp(423, "Interval Too Brief", [("Min-Expires", "60")]))
    with pytest.raises(AuthenticationError):
        await ua.register(account, expires=60)
    assert len(script.requests) == 1


async def test_423_on_unregister_not_retried():
    ua, account, script = _make_ua(
        _resp(423, "Interval Too Brief", [("Min-Expires", "120")]))
    with pytest.raises(AuthenticationError):
        await ua.unregister(account)
    assert len(script.requests) == 1
    assert script.expires() == ["0"]
    assert account._registered is False


async def test_call_id_and_cseq_span_register_and_unregister():
    ua, account, script = _make_ua(_ok(), _ok())
    await ua.register(account)
    await ua.unregister(account)
    assert len(set(script.call_ids())) == 1
    assert script.cseqs() == [1, 2]
    assert script.expires() == ["600", "0"]


async def test_failed_unregister_clears_state_and_task():
    ua, account, script = _make_ua(_ok(), RuntimeError("network down"))
    await ua.register(account)
    with pytest.raises(RuntimeError):
        await ua.unregister(account)
    assert account._registered is False
    assert account._register_task is None


# ---------------------------------------------------------------------------
# Fix 2: register(expires=0) takes unregister semantics
# ---------------------------------------------------------------------------

async def test_register_expires_zero_unregisters_and_cancels_task():
    ua, account, script = _make_ua(_ok(), _ok())
    await ua.register(account)
    assert account._register_task is not None
    assert account._registered is True
    await ua.register(account, expires=0)
    # The refresh task must be gone so it cannot resurrect the binding.
    assert account._register_task is None
    assert account._registered is False
    assert script.expires() == ["600", "0"]


async def test_register_expires_zero_without_existing_task():
    ua, account, script = _make_ua(_ok())
    await ua.register(account, expires=0)
    assert account._register_task is None
    assert account._registered is False
    assert script.expires() == ["0"]


async def test_register_negative_expires_raises_before_send():
    ua, account, script = _make_ua()
    with pytest.raises(ValueError):
        await ua.register(account, expires=-1)
    assert script.requests == []
    assert account._register_task is None
    assert account._registered is False


async def test_register_operations_serialized_per_account():
    # Registrar processing of same-Call-ID REGISTERs is CSeq-order-sensitive
    # (RFC 3261 §10.3 step 6): overlapping register/unregister/refresh sends
    # must not interleave, so _send_register serializes per account.
    ua, account, script = _make_ua(_ok(), _ok())
    in_flight = 0
    max_in_flight = 0
    real = script.send_and_wait

    async def overlapping(req, dest, call_id, cseq_num, timeout=32.0):
        nonlocal in_flight, max_in_flight
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0)  # yield so a concurrent operation can start
        resp = await real(req, dest, call_id, cseq_num, timeout)
        in_flight -= 1
        return resp

    ua._send_and_wait = overlapping
    await asyncio.gather(ua.register(account), ua.register(account))
    assert max_in_flight == 1
    assert script.cseqs() == [1, 2]
    await _drop_refresh_task(account)


# ---------------------------------------------------------------------------
# Refresh loop scheduling (fake clock + recorded sleeps)
# ---------------------------------------------------------------------------

class _Clock:
    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now


def _install_loop_fakes(monkeypatch, clock: _Clock, recorded: list[float],
                        stop_after: int) -> None:
    async def fake_sleep(delay: float) -> None:
        recorded.append(delay)
        clock.now += delay
        if len(recorded) >= stop_after:
            raise asyncio.CancelledError

    monkeypatch.setattr(ua_mod, "_sleep", fake_sleep)
    monkeypatch.setattr(ua_mod, "_monotonic", clock)


def _loop_result(requested: int, granted: int) -> _RegisterResult:
    # Mirror _send_register: the deadline is captured at send time (the fake
    # clock is already installed when this runs), plus the granted interval.
    return _RegisterResult(response=_resp(200), requested_expires=requested,
                           granted_expires=granted,
                           deadline=ua_mod._monotonic() + granted)


async def test_initial_delay_uses_granted_not_requested(monkeypatch):
    ua, account, script = _make_ua()
    account._registered = True
    recorded: list[float] = []
    _install_loop_fakes(monkeypatch, _Clock(), recorded, stop_after=1)
    await ua._reregister_loop(account, _loop_result(requested=600, granted=60))
    assert recorded == [54.0]
    assert script.requests == []


async def test_failed_refresh_retries_within_remaining_validity(monkeypatch):
    ua, account, script = _make_ua(RuntimeError("timeout"))
    account._registered = True
    recorded: list[float] = []
    _install_loop_fakes(monkeypatch, _Clock(), recorded, stop_after=2)
    await ua._reregister_loop(account, _loop_result(requested=600, granted=600))
    # 540 elapsed of a 600s grant leaves 60s; retry at half of that, not
    # after another full refresh interval.
    assert recorded == [540.0, 30.0]


async def test_deadline_recomputed_from_each_response(monkeypatch):
    ua, account, script = _make_ua(_ok(100))
    account._registered = True
    recorded: list[float] = []
    _install_loop_fakes(monkeypatch, _Clock(), recorded, stop_after=2)
    await ua._reregister_loop(account, _loop_result(requested=600, granted=600))
    assert recorded == [540.0, 90.0]


async def test_tiny_grant_failure_retry_beats_deadline(monkeypatch):
    ua, account, script = _make_ua(RuntimeError("timeout"))
    account._registered = True
    recorded: list[float] = []
    _install_loop_fakes(monkeypatch, _Clock(), recorded, stop_after=2)
    await ua._reregister_loop(account, _loop_result(requested=2, granted=2))
    assert recorded == [1.0, 0.5]
    assert sum(recorded) < 2.0


async def test_post_lapse_fixed_rate_and_warning(monkeypatch, caplog):
    ua, account, script = _make_ua(
        RuntimeError("down"), RuntimeError("down"), RuntimeError("down"))
    account._registered = True
    recorded: list[float] = []
    _install_loop_fakes(monkeypatch, _Clock(), recorded, stop_after=4)
    with caplog.at_level(logging.WARNING, logger="opensip.ua"):
        await ua._reregister_loop(account, _loop_result(requested=1, granted=1))
    assert recorded == [0.5, 0.25, 0.25, 5.0]
    assert "may have lapsed" in caplog.text


async def test_refresh_requests_raised_expiry_after_423(monkeypatch):
    ua, account, script = _make_ua(_ok(120))
    account._registered = True
    recorded: list[float] = []
    _install_loop_fakes(monkeypatch, _Clock(), recorded, stop_after=2)
    await ua._reregister_loop(account, _loop_result(requested=120, granted=120))
    assert script.expires() == ["120"]


# ---------------------------------------------------------------------------
# Fix 4: deadline is measured from send time, not response time
# ---------------------------------------------------------------------------

async def test_send_register_deadline_is_send_time_plus_granted(monkeypatch):
    clock = _Clock()  # 1000.0
    monkeypatch.setattr(ua_mod, "_monotonic", clock)
    ua, account, script = _make_ua(_ok(100))
    real = script.send_and_wait

    async def advancing(req, dest, call_id, cseq_num, timeout=32.0):
        resp = await real(req, dest, call_id, cseq_num, timeout)
        clock.now += 10  # RTT elapses after the send
        return resp

    ua._send_and_wait = advancing
    result = await ua._send_register(account, 600)
    # Captured at 1000 (before the send / RTT), granted 100 → 1100,
    # NOT 1110 (the response-arrival time).
    assert result.deadline == 1100.0


async def test_loop_deadline_tracks_send_time_across_rtt(monkeypatch):
    clock = _Clock()  # 1000.0
    recorded: list[float] = []
    ua = UserAgent(local_addr=("127.0.0.1", 5061))
    account = Account(username="alice", domain="example.com", password="pw",
                      server=("127.0.0.1", 5060))
    account._registered = True

    responses = [_ok(200), RuntimeError("down")]

    async def scripted(req, dest, call_id, cseq_num, timeout=32.0):
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        clock.now += 10  # RTT only on a completed round-trip
        return item

    ua._send_and_wait = scripted
    _install_loop_fakes(monkeypatch, clock, recorded, stop_after=3)
    await ua._reregister_loop(account, _loop_result(requested=200, granted=200))
    # Refresh #1 sends at t=1180, grants 200 → deadline 1380 (send-time based).
    # It fails at t=1370, so remaining = 10 → failure delay 5.0.
    # A response-time deadline (1390) would leave remaining 20 → delay 10.0.
    assert recorded == [180.0, 180.0, 5.0]
