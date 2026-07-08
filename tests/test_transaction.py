"""Tests for the RFC 3261 §17.1.2 non-INVITE client transaction layer.

Unit tests drive TransactionManager/NonInviteClientTransaction with a fake
send callable and fake timers (patching opensip.transaction._sleep /
_monotonic — NOT the opensip.ua seams).
"""

import asyncio

import pytest

import opensip.transaction as tx_mod
from opensip.exceptions import TransactionError, TransactionTimeout, TransportError
from opensip.headers import URI
from opensip.message import Headers, SIPRequest, SIPResponse, parse_message
from opensip.transaction import (
    NonInviteClientTransaction,
    TimerConfig,
    TransactionManager,
)
from opensip.ua import Account, Call, UserAgent

DEST = ("127.0.0.1", 5060)
BRANCH = "z9hG4bKtest1"


def _req(method: str = "REGISTER", branch: str = BRANCH) -> SIPRequest:
    h = Headers([
        ("Via", f"SIP/2.0/UDP 127.0.0.1:5061;branch={branch}"),
        ("Call-ID", "cid1"),
        ("CSeq", f"1 {method}"),
    ])
    return SIPRequest(headers=h, method=method, request_uri="sip:example.com")


def _resp(status: int, branch: str = BRANCH, method: str = "REGISTER",
          via: str | None = "default") -> SIPResponse:
    h = Headers()
    if via == "default":
        h.add("Via", f"SIP/2.0/UDP 127.0.0.1:5061;branch={branch}")
    elif via is not None:
        h.add("Via", via)
    h.add("Call-ID", "cid1")
    h.add("CSeq", f"1 {method}")
    return SIPResponse(headers=h, status_code=status, reason="x")


class _FakeSend:
    def __init__(self, fail_on: set[int] | None = None):
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        self.fail_on = fail_on or set()

    async def __call__(self, data: bytes, addr: tuple[str, int]) -> None:
        self.sent.append((data, addr))
        if len(self.sent) in self.fail_on:
            raise TransportError("send failed")


class _Clock:
    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now


def _install_fakes(monkeypatch, clock: _Clock, recorded: list[float]) -> None:
    async def fake_sleep(delay: float) -> None:
        recorded.append(delay)
        clock.now += delay
        await asyncio.sleep(0)  # yield so other tasks can interleave

    monkeypatch.setattr(tx_mod, "_sleep", fake_sleep)
    monkeypatch.setattr(tx_mod, "_monotonic", clock)


async def _spin(n: int = 10) -> None:
    for _ in range(n):
        await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# Timer E / F
# ---------------------------------------------------------------------------

async def test_timer_e_cadence_and_timer_f(monkeypatch):
    recorded: list[float] = []
    _install_fakes(monkeypatch, _Clock(), recorded)
    send = _FakeSend()
    mgr = TransactionManager(send)
    with pytest.raises(TransactionTimeout):
        await mgr.send_request(_req(), DEST)
    # T1-doubling capped at T2, final partial sleep up to Timer F = 32s.
    assert recorded == [0.5, 1.0, 2.0] + [4.0] * 7 + [0.5]
    # 1 initial send + 10 retransmissions, all byte-identical.
    assert len(send.sent) == 11
    assert len({data for data, _ in send.sent}) == 1
    assert all(addr == DEST for _, addr in send.sent)
    assert len(mgr) == 0


async def test_provisional_pins_interval_to_t2(monkeypatch):
    recorded: list[float] = []
    _install_fakes(monkeypatch, _Clock(), recorded)
    send = _FakeSend()
    tx = NonInviteClientTransaction(_req(), DEST, send, TimerConfig())
    assert tx.on_response(_resp(100)) is True     # Trying -> Proceeding
    assert tx.state == tx_mod.PROCEEDING
    await tx.start()
    with pytest.raises(TransactionTimeout):
        await tx.wait()
    # First Timer E still fires at T1; every subsequent firing is T2.
    assert recorded == [0.5] + [4.0] * 7 + [3.5]


async def test_timer_f_override(monkeypatch):
    recorded: list[float] = []
    _install_fakes(monkeypatch, _Clock(), recorded)
    mgr = TransactionManager(_FakeSend())
    with pytest.raises(TransactionTimeout, match="1.0s"):
        await mgr.send_request(_req(), DEST, timer_f=1.0)
    assert recorded == [0.5, 0.5]


# ---------------------------------------------------------------------------
# Final responses / Timer K
# ---------------------------------------------------------------------------

async def test_final_resolves_duplicates_absorbed_timer_k(monkeypatch):
    recorded: list[float] = []
    _install_fakes(monkeypatch, _Clock(), recorded)
    mgr = TransactionManager(_FakeSend())
    task = asyncio.create_task(mgr.send_request(_req(), DEST))
    await _spin(2)
    assert len(mgr) == 1
    assert mgr.dispatch_response(_resp(200)) is True
    resp = await task
    assert resp.status_code == 200
    # Duplicate final while Completed: consumed, result unchanged.
    assert mgr.dispatch_response(_resp(200)) is True
    # Timer K (T4) then removal from the manager.
    await _spin()
    assert 5.0 in recorded
    assert len(mgr) == 0
    # After Terminated the transaction no longer consumes anything.
    assert mgr.dispatch_response(_resp(200)) is False


# ---------------------------------------------------------------------------
# Transport errors
# ---------------------------------------------------------------------------

async def test_first_send_failure_propagates_and_unregisters(monkeypatch):
    _install_fakes(monkeypatch, _Clock(), [])
    mgr = TransactionManager(_FakeSend(fail_on={1}))
    with pytest.raises(TransportError):
        await mgr.send_request(_req(), DEST)
    assert len(mgr) == 0


async def test_retransmit_send_failure_fails_future(monkeypatch):
    recorded: list[float] = []
    _install_fakes(monkeypatch, _Clock(), recorded)
    mgr = TransactionManager(_FakeSend(fail_on={2}))
    with pytest.raises(TransportError):
        await mgr.send_request(_req(), DEST)
    assert recorded == [0.5]
    assert len(mgr) == 0


# ---------------------------------------------------------------------------
# Matching (§17.1.3)
# ---------------------------------------------------------------------------

async def test_matching_negatives(monkeypatch):
    _install_fakes(monkeypatch, _Clock(), [])
    mgr = TransactionManager(_FakeSend())
    task = asyncio.create_task(mgr.send_request(_req(), DEST))
    await _spin(2)
    assert mgr.dispatch_response(_resp(200, branch="z9hG4bKother")) is False
    assert mgr.dispatch_response(_resp(200, method="OPTIONS")) is False
    assert mgr.dispatch_response(_resp(200, via=None)) is False
    assert mgr.dispatch_response(_resp(200, via="garbage")) is False
    bad_cseq = _resp(200)
    bad_cseq.headers.set("CSeq", "bogus")
    assert mgr.dispatch_response(bad_cseq) is False
    # The transaction is still alive and matches the real response.
    assert mgr.dispatch_response(_resp(200)) is True
    assert (await task).status_code == 200


async def test_request_without_branch_rejected():
    req = _req()
    req.headers.set("Via", "SIP/2.0/UDP 127.0.0.1:5061")
    with pytest.raises(TransactionError):
        NonInviteClientTransaction(req, DEST, _FakeSend(), TimerConfig())


# ---------------------------------------------------------------------------
# Termination
# ---------------------------------------------------------------------------

async def test_terminate_all_fails_pending_futures(monkeypatch):
    _install_fakes(monkeypatch, _Clock(), [])
    mgr = TransactionManager(_FakeSend())
    t1 = asyncio.create_task(mgr.send_request(_req(branch="z9hG4bKa"), DEST))
    t2 = asyncio.create_task(mgr.send_request(_req(method="BYE", branch="z9hG4bKb"), DEST))
    await _spin(2)
    assert len(mgr) == 2
    mgr.terminate_all()
    with pytest.raises(TransactionError, match="user agent stopped"):
        await t1
    with pytest.raises(TransactionError, match="user agent stopped"):
        await t2
    assert len(mgr) == 0


async def test_awaiter_cancellation_terminates_transaction(monkeypatch):
    _install_fakes(monkeypatch, _Clock(), [])
    mgr = TransactionManager(_FakeSend())
    task = asyncio.create_task(mgr.send_request(_req(), DEST))
    await _spin(2)
    tx = next(iter(mgr._transactions.values()))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert tx.state == tx_mod.TERMINATED
    assert tx._retransmit_task is None
    assert len(mgr) == 0


# ---------------------------------------------------------------------------
# UserAgent integration (real manager, fake send, real timers — the response
# arrives well inside the first 0.5s Timer E window)
# ---------------------------------------------------------------------------

def _make_ua() -> tuple[UserAgent, _FakeSend]:
    ua = UserAgent(local_addr=("127.0.0.1", 5061))
    send = _FakeSend()
    ua._transactions._send = send
    return ua, send


async def test_ua_matches_response_by_branch_not_call_id():
    ua, _ = _make_ua()
    task = asyncio.create_task(
        ua._send_and_wait(_req(), ("127.0.0.1", 5060), "cid1", 1))
    await _spin(2)
    # Same Call-ID and CSeq but a different branch: must NOT resolve.
    ua._on_message(_resp(200, branch="z9hG4bKother"), ("127.0.0.1", 5060))
    await _spin(2)
    assert not task.done()
    ua._on_message(_resp(200), ("127.0.0.1", 5060))
    assert (await task).status_code == 200
    ua._transactions.terminate_all()  # cancel the Timer-K absorber


async def test_ua_stop_fails_inflight_waiters_and_cancels_refresh():
    ua, _ = _make_ua()
    account = Account(username="alice", domain="example.com", password="pw",
                      server=("127.0.0.1", 5060))
    refresh = asyncio.create_task(asyncio.sleep(3600))
    account._register_task = refresh
    ua._accounts.append(account)
    task = asyncio.create_task(
        ua._send_and_wait(_req(), ("127.0.0.1", 5060), "cid1", 1))
    await _spin(2)
    await ua.stop()
    with pytest.raises(TransactionError, match="user agent stopped"):
        await task
    assert account._register_task is None
    assert refresh.cancelled() or refresh.done()


async def test_ua_stop_marks_accounts_unregistered():
    # stop() ends registration maintenance, so the observable state must
    # follow (mirrors _registered semantics: local maintenance state, not
    # registrar truth — the binding may still exist server-side).
    ua, _ = _make_ua()
    account = Account(username="alice", domain="example.com", password="pw",
                      server=("127.0.0.1", 5060))
    account._registered = True
    account._registration_state = "registered"
    ua._accounts.append(account)
    events: list[str] = []
    ua.on_registration_state(lambda acc, state: events.append(state))
    await ua.stop()
    assert account._registered is False
    assert account.registration_state == "unregistered"
    assert events == ["unregistered"]


async def test_duplicate_transaction_key_rejected(monkeypatch):
    # A Via-branch collision must fail loudly, not silently orphan the
    # in-flight transaction by overwriting its table entry.
    clock = _Clock()
    recorded: list[float] = []
    _install_fakes(monkeypatch, clock, recorded)
    send = _FakeSend()
    mgr = TransactionManager(send)
    task = asyncio.create_task(mgr.send_request(_req(), DEST))
    await _spin(2)
    with pytest.raises(TransactionError, match="duplicate"):
        await mgr.send_request(_req(), DEST)
    # The original transaction is unaffected and still completes.
    assert mgr.dispatch_response(_resp(200))
    assert (await task).status_code == 200
    mgr.terminate_all()  # cancel the Timer-K absorber


async def test_send_bye_swallows_transaction_timeout():
    ua, _ = _make_ua()
    account = Account(username="alice", domain="example.com", password="pw",
                      server=("127.0.0.1", 5060))

    async def raise_timeout(req, dest, call_id, cseq_num, timeout=None):
        raise TransactionTimeout("BYE timed out (Timer F)")

    ua._send_and_wait = raise_timeout
    call = Call(ua, account, outbound=True)
    call.call_id = "cid-bye"
    call.cseq = 1
    call.remote_uri = URI.parse("sip:bob@example.com")
    await ua._send_bye(call)   # must not raise


# ---------------------------------------------------------------------------
# Live loopback (real UDP, shrunk timers; generous assertions for WSL jitter)
# ---------------------------------------------------------------------------

class _Responder(asyncio.DatagramProtocol):
    """Drops the first ``drop`` datagrams, then answers each with 200 OK."""

    def __init__(self, drop: int):
        self.drop = drop
        self.received: list[bytes] = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.received.append(data)
        if len(self.received) <= self.drop:
            return
        req = parse_message(data)
        h = Headers()
        for name in ("Via", "From", "Call-ID", "CSeq"):
            h.add(name, req.headers.get(name))
        h.add("To", req.headers.get("To") + ";tag=live1")
        resp = SIPResponse(headers=h, status_code=200, reason="OK")
        self.transport.sendto(resp.encode(), addr)


async def _live_pair(drop: int, t1: float) -> tuple[UserAgent, Account, _Responder]:
    loop = asyncio.get_running_loop()
    transport, responder = await loop.create_datagram_endpoint(
        lambda: _Responder(drop), local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    ua = UserAgent(local_addr=("127.0.0.1", 0),
                   timers=TimerConfig(t1=t1, t4=0.05))
    await ua.start()
    account = Account(username="alice", domain="127.0.0.1", password="pw",
                      server=("127.0.0.1", port))
    return ua, account, responder


async def test_live_retransmit_until_response():
    ua, account, responder = await _live_pair(drop=2, t1=0.05)
    try:
        await ua.register(account)   # succeeds only via retransmission
        assert account._registered
        assert len(responder.received) >= 3
        # Retransmissions are byte-identical to the original datagram.
        assert responder.received[0] == responder.received[1] == responder.received[2]
    finally:
        await ua.stop()


async def test_live_timer_f_timeout():
    ua, account, responder = await _live_pair(drop=10**9, t1=0.01)  # silent peer
    try:
        with pytest.raises(TransactionTimeout):
            await ua.register(account)
        assert len(responder.received) >= 2   # original + at least one retransmit
        assert not account._registered
    finally:
        await ua.stop()
