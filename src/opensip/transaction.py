"""RFC 3261 §17.1.2 non-INVITE client transactions over UDP.

The transport layer speaks single datagrams; this layer owns reliability
for non-INVITE requests (REGISTER, BYE, OPTIONS, ...):

  * Timer E — retransmit the request at T1, doubling up to T2 (pinned to
    T2 once a provisional response arrives).
  * Timer F — give up after 64*T1 without a final response.
  * Timer K — after a final response, linger for T4 to absorb
    retransmitted duplicates of that final response.

INVITE transactions are NOT handled here — the UA keeps its own
per-call INVITE future path.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

from .exceptions import SIPParseError, TransactionError, TransactionTimeout
from .headers import parse_via_list
from .message import SIPRequest, SIPResponse

log = logging.getLogger("opensip.transaction")

# RFC 3261 Appendix A default timer values (seconds).
T1 = 0.5   # RTT estimate
T2 = 4.0   # maximum retransmit interval for non-INVITE requests
T4 = 5.0   # maximum time a message stays in the network

# Testability seams: transactions sleep and read the clock through these so
# tests can monkeypatch opensip.transaction._sleep / _monotonic. NOTE:
# distinct from the opensip.ua._sleep/_monotonic seams — patch the module
# that owns the code under test.
_sleep = asyncio.sleep
_monotonic = time.monotonic

SendFn = Callable[[bytes, tuple[str, int]], Awaitable[None]]

TRYING = "trying"
PROCEEDING = "proceeding"
COMPLETED = "completed"
TERMINATED = "terminated"


@dataclass(frozen=True)
class TimerConfig:
    """RFC 3261 timer values; shrink t1/t4 for fast tests."""

    t1: float = T1
    t2: float = T2
    t4: float = T4

    @property
    def timer_f(self) -> float:
        """Transaction timeout (64*T1)."""
        return 64.0 * self.t1


def _branch_of(msg: SIPRequest | SIPResponse) -> str | None:
    """Top-Via branch parameter, or None if absent/unparsable."""
    raw = msg.headers.get("Via")
    if not raw:
        return None
    try:
        vias = parse_via_list(raw)
    except (SIPParseError, ValueError):
        return None
    if not vias:
        return None
    return vias[0].params.get("branch")


class NonInviteClientTransaction:
    """One in-flight non-INVITE request (RFC 3261 §17.1.2)."""

    def __init__(
        self,
        request: SIPRequest,
        dest: tuple[str, int],
        send: SendFn,
        timers: TimerConfig,
        *,
        timer_f: float | None = None,
        on_terminated: Callable[["NonInviteClientTransaction"], None] | None = None,
    ):
        branch = _branch_of(request)
        if not branch:
            raise TransactionError(f"{request.method} request has no Via branch")
        self.branch = branch
        self.method = request.method
        self.key = (branch, self.method)
        self.state = TRYING
        self._data = request.encode()   # retransmissions are byte-identical
        self._dest = dest
        self._send = send
        self._timers = timers
        self._timer_f = timer_f if timer_f is not None else timers.timer_f
        self._on_terminated = on_terminated
        self._future: asyncio.Future[SIPResponse] = (
            asyncio.get_running_loop().create_future())
        self._retransmit_task: asyncio.Task | None = None
        self._absorb_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Send the request once and arm Timers E/F.

        A failure of this first send propagates directly to the caller."""
        await self._send(self._data, self._dest)
        self._retransmit_task = asyncio.create_task(self._retransmit_loop())

    async def wait(self) -> SIPResponse:
        """Await the final response (or transaction failure)."""
        try:
            return await self._future
        except asyncio.CancelledError:
            # The awaiter went away; don't leave a live retransmitting task.
            self.terminate()
            raise

    def on_response(self, resp: SIPResponse) -> bool:
        """Feed a matched response into the transaction.

        Returns True if the response was consumed."""
        if self.state == TERMINATED:
            return False
        if resp.status_code < 200:
            if self.state == TRYING:
                # §17.1.2.2: after a provisional response, Timer E resets
                # to T2 on each subsequent firing.
                self.state = PROCEEDING
            return True
        if self.state in (TRYING, PROCEEDING):
            self.state = COMPLETED
            if self._retransmit_task:
                self._retransmit_task.cancel()
                self._retransmit_task = None
            if not self._future.done():
                self._future.set_result(resp)
            # Timer K: linger to absorb retransmitted finals.
            self._absorb_task = asyncio.create_task(self._absorb_then_terminate())
            return True
        # COMPLETED: duplicate final response — absorb silently.
        return True

    def terminate(self, exc: BaseException | None = None) -> None:
        """Tear the transaction down (idempotent).

        With ``exc``, a still-pending future fails with it; without, the
        future is cancelled (used when the awaiter itself has gone away,
        so nothing would ever retrieve an exception)."""
        if self.state == TERMINATED:
            return
        self.state = TERMINATED
        current = asyncio.current_task()
        for task in (self._retransmit_task, self._absorb_task):
            if task is not None and task is not current:
                task.cancel()
        self._retransmit_task = self._absorb_task = None
        if not self._future.done():
            if exc is not None:
                self._future.set_exception(exc)
            else:
                self._future.cancel()
        if self._on_terminated:
            self._on_terminated(self)

    async def _retransmit_loop(self) -> None:
        # Timers E and F.
        deadline = _monotonic() + self._timer_f
        interval = self._timers.t1
        while True:
            remaining = deadline - _monotonic()
            if remaining <= 0:
                self.terminate(TransactionTimeout(
                    f"{self.method} timed out after {self._timer_f:.1f}s (Timer F)"))
                return
            await _sleep(min(interval, remaining))
            if self.state not in (TRYING, PROCEEDING):
                return  # final response landed mid-sleep
            if deadline - _monotonic() <= 0:
                self.terminate(TransactionTimeout(
                    f"{self.method} timed out after {self._timer_f:.1f}s (Timer F)"))
                return
            try:
                await self._send(self._data, self._dest)
            except Exception as e:
                self.terminate(e)
                return
            if self.state == PROCEEDING:
                interval = self._timers.t2
            else:
                interval = min(interval * 2, self._timers.t2)

    async def _absorb_then_terminate(self) -> None:
        # Timer K.
        await _sleep(self._timers.t4)
        self.state = TERMINATED
        self._absorb_task = None
        if self._on_terminated:
            self._on_terminated(self)


class TransactionManager:
    """Owns live non-INVITE client transactions, keyed by (branch, method)."""

    def __init__(self, send: SendFn, timers: TimerConfig | None = None):
        self._send = send
        self.timers = timers or TimerConfig()
        self._transactions: dict[tuple[str, str], NonInviteClientTransaction] = {}

    async def send_request(self, req: SIPRequest, dest: tuple[str, int],
                           *, timer_f: float | None = None) -> SIPResponse:
        """Run one non-INVITE client transaction to its final response."""
        tx = NonInviteClientTransaction(
            req, dest, self._send, self.timers,
            timer_f=timer_f, on_terminated=self._remove)
        if tx.key in self._transactions:
            # new_branch() makes collisions astronomically unlikely; if one
            # ever happens, fail loudly rather than silently orphaning the
            # in-flight transaction by overwriting its table entry.
            raise TransactionError(
                f"duplicate transaction key {tx.key!r} (Via branch collision)")
        self._transactions[tx.key] = tx
        try:
            await tx.start()
        except BaseException:
            tx.terminate()
            raise
        return await tx.wait()

    def dispatch_response(self, resp: SIPResponse) -> bool:
        """Route a response to its transaction (RFC 3261 §17.1.3: top-Via
        branch + CSeq method). Returns True if consumed."""
        branch = _branch_of(resp)
        if not branch:
            return False
        try:
            cseq = resp.cseq
        except SIPParseError:
            return False
        if not cseq:
            return False
        tx = self._transactions.get((branch, cseq[1]))
        if tx is None:
            return False
        return tx.on_response(resp)

    def terminate_all(self, reason: str = "user agent stopped") -> None:
        for tx in list(self._transactions.values()):
            tx.terminate(TransactionError(reason))

    def _remove(self, tx: NonInviteClientTransaction) -> None:
        if self._transactions.get(tx.key) is tx:
            del self._transactions[tx.key]

    def __len__(self) -> int:
        return len(self._transactions)


__all__ = [
    "TimerConfig",
    "NonInviteClientTransaction",
    "TransactionManager",
    "T1",
    "T2",
    "T4",
]
