"""High-level SIP User Agent (UAC + UAS).

This module wires together :mod:`transport`, :mod:`message`, :mod:`auth`,
:mod:`sdp`, and :mod:`rtp` into a small ergonomic API:

    ua = UserAgent(local_addr=("0.0.0.0", 5060))
    await ua.start()
    acc = Account(username="alice", domain="sip.example.com",
                  password="...", server=("sip.example.com", 5060))
    await ua.register(acc)
    call = await ua.invite(acc, "sip:bob@sip.example.com")
    await call.wait_answered()
    ...
    await call.hangup()

Scope of v0.1:
  * single ongoing call per account
  * INVITE/ACK/BYE + REGISTER
  * digest auth on REGISTER / INVITE / BYE
  * RTP audio with PCMU/PCMA codecs
  * incoming INVITE delivered to a user-supplied callback
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from .auth import Challenge, build_authorization
from .exceptions import AuthenticationError, OpenSIPError, TransactionError
from .headers import NameAddr, URI, Via
from .message import Headers, SIPRequest, SIPResponse
from .rtp import DTMF_DEFAULT_PT, RTPSession, pick_rtp_port_pair
from .sdp import Codec, SDPSession, make_audio_offer, pick_common_codec
from .transport import UDPTransport
from .utils import guess_local_ip, new_branch, new_call_id, new_tag

log = logging.getLogger("opensip.ua")

USER_AGENT = "opensip/0.2.1"
DEFAULT_REGISTER_EXPIRES = 600
DEFAULT_INVITE_TIMEOUT = 32.0


def _dtmf_pt_from_sdp(sdp: SDPSession | None, default: int = DTMF_DEFAULT_PT) -> int:
    """Find the peer's telephone-event payload type; fall back to 101."""
    if not sdp or not sdp.media:
        return default
    for c in sdp.media[0].codecs:
        if c.name.lower() == "telephone-event":
            return c.payload_type
    return default


# ---------------------------------------------------------------------------
@dataclass
class Account:
    username: str
    domain: str
    password: str
    server: tuple[str, int] = ("", 5060)
    display: str | None = None
    expires: int = DEFAULT_REGISTER_EXPIRES
    transport: str = "UDP"

    # ----- runtime state, populated by the UA -----
    _registered: bool = field(default=False, init=False, repr=False)
    _register_task: asyncio.Task | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.server[0]:
            self.server = (self.domain, self.server[1] or 5060)

    @property
    def aor(self) -> str:
        """Address-of-record (sip:user@domain)."""
        return f"sip:{self.username}@{self.domain}"


# ---------------------------------------------------------------------------
class Call:
    """Represents one SIP dialog (outgoing or incoming) for audio."""

    State = ("init", "calling", "ringing", "answered", "ended", "failed")

    def __init__(self, ua: "UserAgent", account: Account, *, outbound: bool):
        self.ua = ua
        self.account = account
        self.outbound = outbound

        self.call_id: str = ""
        self.local_tag: str = new_tag()
        self.remote_tag: str = ""
        self.local_uri: URI = URI()
        self.remote_uri: URI = URI()
        self.remote_target: URI = URI()
        self.cseq: int = 0
        self.invite_request: SIPRequest | None = None    # last sent / received INVITE
        self.invite_response: SIPResponse | None = None  # last 2xx
        self.route_set: list[str] = []
        self.contact: str = ""

        self.state: str = "init"
        self._answered = asyncio.Event()
        self._ended = asyncio.Event()
        self._failed_reason: str | None = None

        self.rtp: RTPSession | None = None
        self.local_sdp: SDPSession | None = None
        self.remote_sdp: SDPSession | None = None
        self.codec: Codec | None = None

        # For inbound calls: the source UDP address that delivered the INVITE.
        # All UAS responses (180/200/...) and reverse requests use this.
        self.source: tuple[str, int] | None = None

        self._pending_invite_response: asyncio.Future[SIPResponse] | None = None
        self._auth_retried = False

    # ------------------------------------------------------------------
    async def wait_answered(self, timeout: float | None = None) -> None:
        await asyncio.wait_for(self._answered.wait(), timeout=timeout)
        if self.state in ("failed", "ended"):
            raise TransactionError(self._failed_reason or "call failed")

    async def wait_ended(self) -> None:
        await self._ended.wait()

    @property
    def is_active(self) -> bool:
        return self.state == "answered"

    # ------------------------------------------------------------------
    # Audio helpers
    # ------------------------------------------------------------------
    def write_pcm(self, pcm: bytes) -> None:
        if self.rtp:
            self.rtp.write_pcm(pcm)

    def on_pcm(self, callback) -> None:
        if self.rtp:
            self.rtp.set_on_pcm(callback)

    def on_dtmf(self, callback) -> None:
        """Register a callback for inbound DTMF digits (RFC 4733)."""
        if self.rtp:
            self.rtp.set_on_dtmf(callback)

    async def send_dtmf(
        self, digits: str, duration_ms: int = 160, gap_ms: int = 80,
        volume: int = 10,
    ) -> None:
        """Send one or more DTMF digits via RFC 4733 telephone-event.

        ``digits`` is any string of ``0-9``, ``*``, ``#``, ``A-D``. ``gap_ms``
        is the silent gap inserted between consecutive digits.
        """
        if not self.rtp:
            raise OpenSIPError("call has no active RTP session")
        gap = max(0.0, gap_ms / 1000.0)
        for i, d in enumerate(digits):
            if i > 0 and gap:
                await asyncio.sleep(gap)
            await self.rtp.send_dtmf(d, duration_ms=duration_ms, volume=volume)

    # ------------------------------------------------------------------
    # Outgoing actions
    # ------------------------------------------------------------------
    async def answer(self) -> None:
        if not self.outbound:
            await self.ua._answer_call(self)
        else:
            raise OpenSIPError("cannot answer an outbound call")

    async def hangup(self) -> None:
        await self.ua._hangup_call(self)


# ---------------------------------------------------------------------------
class UserAgent:
    """Top-level SIP user agent — speaks UDP only in v0.1."""

    def __init__(
        self,
        *,
        local_addr: tuple[str, int] = ("0.0.0.0", 5060),
        user_agent: str = USER_AGENT,
        rtp_port_range: tuple[int, int] = (16384, 32767),
    ):
        self.transport = UDPTransport(local_addr=local_addr)
        self.user_agent_header = user_agent
        self.rtp_port_range = rtp_port_range

        self._calls: dict[str, Call] = {}             # call-id -> Call
        self._pending_responses: dict[tuple[str, int], asyncio.Future] = {}
        # ↑ keyed by (call-id, cseq) for non-INVITE; INVITEs use Call._pending_invite_response

        self._accounts: list[Account] = []
        self._incoming_call_cb: Callable[[Call], Awaitable[None]] | None = None
        self._stopped = False

        self.transport.set_handler(self._on_message)

    # ------------------------------------------------------------------
    @property
    def local_addr(self) -> tuple[str, int]:
        return self.transport.local_addr

    async def start(self) -> None:
        await self.transport.start()

    async def stop(self) -> None:
        self._stopped = True
        for call in list(self._calls.values()):
            try:
                await self._hangup_call(call)
            except Exception:
                pass
        await self.transport.stop()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def on_incoming_call(self, cb: Callable[[Call], Awaitable[None]]):
        """Decorator/setter for the incoming-INVITE handler."""
        self._incoming_call_cb = cb
        return cb

    async def register(self, account: Account, *, expires: int | None = None) -> None:
        """Send REGISTER (with digest re-auth on 401/407)."""
        if expires is None:
            expires = account.expires
        if account not in self._accounts:
            self._accounts.append(account)
        await self._send_register(account, expires)
        if expires > 0:
            account._registered = True
            # Schedule auto-refresh at expires/2.
            if account._register_task:
                account._register_task.cancel()
            account._register_task = asyncio.create_task(
                self._reregister_loop(account, expires)
            )

    async def unregister(self, account: Account) -> None:
        if account._register_task:
            account._register_task.cancel()
            account._register_task = None
        try:
            await self._send_register(account, 0)
        finally:
            account._registered = False

    async def invite(self, account: Account, target: str) -> Call:
        """Place an outgoing call. Returns once the dialog is set up enough to
        track. Use :meth:`Call.wait_answered` to block for the 200 OK."""
        call = Call(self, account, outbound=True)
        call.local_uri = URI.parse(account.aor)
        call.remote_uri = URI.parse(target)
        call.call_id = new_call_id(self.local_addr[0])
        call.cseq = 1
        self._calls[call.call_id] = call

        await self._send_invite(call)
        return call

    # ------------------------------------------------------------------
    # Inbound message routing
    # ------------------------------------------------------------------
    def _on_message(self, msg, source: tuple[str, int]) -> None:
        if isinstance(msg, SIPResponse):
            self._dispatch_response(msg, source)
        else:
            self._dispatch_request(msg, source)

    def _dispatch_response(self, resp: SIPResponse, source: tuple[str, int]) -> None:
        call_id = resp.call_id or ""
        cseq = resp.cseq or (0, "")
        log.debug("← %d %s for %s CSeq %s", resp.status_code, resp.reason,
                  call_id, cseq)

        call = self._calls.get(call_id)
        if call and call._pending_invite_response and cseq[1] == "INVITE":
            if not call._pending_invite_response.done():
                # provisional responses can be observed too
                if 100 <= resp.status_code < 200:
                    if resp.status_code == 180:
                        call.state = "ringing"
                    return
                call._pending_invite_response.set_result(resp)
            return

        fut = self._pending_responses.get((call_id, cseq[0]))
        if fut and not fut.done():
            if 100 <= resp.status_code < 200:
                return
            fut.set_result(resp)

    def _dispatch_request(self, req: SIPRequest, source: tuple[str, int]) -> None:
        method = req.method
        log.debug("← %s from %s:%d", method, *source)
        try:
            if method == "INVITE":
                asyncio.create_task(self._handle_incoming_invite(req, source))
            elif method == "ACK":
                asyncio.create_task(self._handle_incoming_ack(req, source))
            elif method == "BYE":
                asyncio.create_task(self._handle_incoming_bye(req, source))
            elif method == "CANCEL":
                asyncio.create_task(self._handle_incoming_cancel(req, source))
            elif method == "OPTIONS":
                asyncio.create_task(self._respond(req, 200, "OK", source))
            else:
                asyncio.create_task(self._respond(req, 501, "Not Implemented", source))
        except Exception:
            log.exception("error handling %s", method)

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------
    def _local_contact_uri(self, account: Account) -> URI:
        ip = self.local_addr[0]
        if ip in ("0.0.0.0", "::"):
            ip = guess_local_ip(account.server)
        return URI(user=account.username, host=ip, port=self.local_addr[1])

    def _build_request(
        self,
        method: str,
        request_uri: str | URI,
        *,
        account: Account,
        call_id: str,
        cseq_num: int,
        from_addr: NameAddr,
        to_addr: NameAddr,
        extra_headers: list[tuple[str, str]] | None = None,
        body: bytes = b"",
        content_type: str | None = None,
        branch: str | None = None,
    ) -> SIPRequest:
        headers = Headers()
        local_ip = self.local_addr[0]
        if local_ip in ("0.0.0.0", "::"):
            local_ip = guess_local_ip(account.server)
        via = Via(transport=account.transport, host=local_ip,
                  port=self.local_addr[1],
                  params={"branch": branch or new_branch(), "rport": ""})
        headers.add("Via", str(via))
        headers.add("Max-Forwards", "70")
        headers.add("From", str(from_addr))
        headers.add("To", str(to_addr))
        headers.add("Call-ID", call_id)
        headers.add("CSeq", f"{cseq_num} {method}")
        headers.add("Contact", f"<{self._local_contact_uri(account)}>")
        headers.add("User-Agent", self.user_agent_header)
        for k, v in (extra_headers or []):
            headers.add(k, v)
        req = SIPRequest(
            method=method,
            request_uri=str(request_uri),
            headers=headers,
        )
        if body:
            req.set_body(body, content_type)
        else:
            headers.set("Content-Length", "0")
        return req

    # ------------------------------------------------------------------
    # REGISTER
    # ------------------------------------------------------------------
    async def _send_register(self, account: Account, expires: int) -> SIPResponse:
        call_id = new_call_id(self.local_addr[0])
        cseq = 1
        from_addr = NameAddr(display=account.display,
                             uri=URI.parse(account.aor),
                             params={"tag": new_tag()})
        to_addr = NameAddr(uri=URI.parse(account.aor))
        registrar_uri = URI(host=account.domain)

        async def do_send(auth_header: tuple[str, str] | None = None) -> SIPResponse:
            extra = [("Expires", str(expires)), ("Allow",
                     "INVITE, ACK, CANCEL, BYE, OPTIONS")]
            if auth_header:
                extra.append(auth_header)
            req = self._build_request(
                "REGISTER", registrar_uri,
                account=account, call_id=call_id, cseq_num=cseq,
                from_addr=from_addr, to_addr=to_addr,
                extra_headers=extra,
            )
            return await self._send_and_wait(req, account.server, call_id, cseq)

        resp = await do_send()
        if resp.status_code in (401, 407):
            auth = self._build_auth_header_from_response(
                resp, method="REGISTER", uri=str(registrar_uri),
                account=account)
            # SIP requires a new CSeq for the re-tried request.
            cseq += 1
            resp = await do_send(auth)
        if resp.status_code >= 300:
            raise AuthenticationError(
                f"REGISTER failed: {resp.status_code} {resp.reason}"
            )
        return resp

    async def _reregister_loop(self, account: Account, expires: int) -> None:
        try:
            while not self._stopped and account._registered:
                # Refresh at half the expires window, min 30s.
                await asyncio.sleep(max(30, expires // 2))
                try:
                    await self._send_register(account, expires)
                except Exception as e:
                    log.warning("re-REGISTER failed: %s", e)
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # Outgoing INVITE
    # ------------------------------------------------------------------
    async def _send_invite(self, call: Call) -> None:
        account = call.account

        # Allocate RTP port + build SDP offer.
        local_ip = self.local_addr[0]
        if local_ip in ("0.0.0.0", "::"):
            local_ip = guess_local_ip(account.server)
        rtp_port = pick_rtp_port_pair(host=local_ip,
                                      low=self.rtp_port_range[0],
                                      high=self.rtp_port_range[1])
        call.local_sdp = make_audio_offer(local_ip, rtp_port)
        body = call.local_sdp.encode()

        from_addr = NameAddr(display=account.display,
                             uri=URI.parse(account.aor),
                             params={"tag": call.local_tag})
        to_addr = NameAddr(uri=call.remote_uri)

        async def send_once(auth_header: tuple[str, str] | None = None) -> SIPResponse:
            call._pending_invite_response = asyncio.get_running_loop().create_future()
            extra = [("Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS")]
            if auth_header:
                extra.append(auth_header)
            req = self._build_request(
                "INVITE", call.remote_uri,
                account=account, call_id=call.call_id, cseq_num=call.cseq,
                from_addr=from_addr, to_addr=to_addr,
                extra_headers=extra,
                body=body, content_type="application/sdp",
            )
            call.invite_request = req
            call.state = "calling"
            await self.transport.send(req.encode(), account.server)
            try:
                return await asyncio.wait_for(
                    call._pending_invite_response, timeout=DEFAULT_INVITE_TIMEOUT
                )
            except asyncio.TimeoutError as e:
                call.state = "failed"
                call._failed_reason = "INVITE timed out"
                call._answered.set()
                call._ended.set()
                raise TransactionError("INVITE timed out") from e

        resp = await send_once()
        # Auth challenge?
        if resp.status_code in (401, 407) and not call._auth_retried:
            call._auth_retried = True
            await self._send_ack_for_failure(call, resp, account.server)
            call.cseq += 1
            auth = self._build_auth_header_from_response(
                resp, method="INVITE", uri=str(call.remote_uri),
                account=account, body=body)
            resp = await send_once(auth)

        if 200 <= resp.status_code < 300:
            await self._on_invite_success(call, resp)
        else:
            call.state = "failed"
            call._failed_reason = f"{resp.status_code} {resp.reason}"
            call._answered.set()
            call._ended.set()
            await self._send_ack_for_failure(call, resp, account.server)
            self._calls.pop(call.call_id, None)
            raise TransactionError(call._failed_reason)

    async def _on_invite_success(self, call: Call, resp: SIPResponse) -> None:
        call.invite_response = resp
        to_addr = NameAddr.parse(resp.headers.get("To") or "")
        call.remote_tag = to_addr.params.get("tag", "")
        contact_raw = resp.headers.get("Contact")
        if contact_raw:
            try:
                call.remote_target = NameAddr.parse(contact_raw).uri
            except Exception:
                call.remote_target = call.remote_uri
        else:
            call.remote_target = call.remote_uri

        # parse remote SDP & set up RTP
        if resp.body:
            try:
                call.remote_sdp = SDPSession.parse(resp.body)
            except Exception as e:
                log.warning("bad SDP in 200 OK: %s", e)
        if call.local_sdp and call.remote_sdp:
            call.codec = pick_common_codec(call.local_sdp, call.remote_sdp)
            if call.codec is None:
                call._failed_reason = "no common codec"
                call.state = "failed"
                call._answered.set()
                call._ended.set()
                await self._send_bye(call)
                return

            local_ip = call.local_sdp.address
            local_port = call.local_sdp.media[0].port
            remote_addr = (
                call.remote_sdp.media[0].connection[1]
                if call.remote_sdp.media[0].connection
                else call.remote_sdp.address,
                call.remote_sdp.media[0].port,
            )
            rtp = RTPSession(
                local_addr=(local_ip, local_port),
                payload_type=call.codec.payload_type,
                codec_name=call.codec.name,
                dtmf_payload_type=_dtmf_pt_from_sdp(call.remote_sdp),
            )
            await rtp.start()
            rtp.set_remote(remote_addr)
            call.rtp = rtp

        # Send ACK (end-to-end, may differ from INVITE's route)
        await self._send_ack(call)
        call.state = "answered"
        call._answered.set()

    # ------------------------------------------------------------------
    # ACK / BYE / CANCEL
    # ------------------------------------------------------------------
    async def _send_ack(self, call: Call) -> None:
        account = call.account
        from_addr = NameAddr(display=account.display,
                             uri=URI.parse(account.aor),
                             params={"tag": call.local_tag})
        to_params = {"tag": call.remote_tag} if call.remote_tag else {}
        to_addr = NameAddr(uri=call.remote_uri, params=to_params)

        headers = Headers()
        local_ip = self.local_addr[0]
        if local_ip in ("0.0.0.0", "::"):
            local_ip = guess_local_ip(account.server)
        via = Via(transport=account.transport, host=local_ip,
                  port=self.local_addr[1],
                  params={"branch": new_branch(), "rport": ""})
        headers.add("Via", str(via))
        headers.add("Max-Forwards", "70")
        headers.add("From", str(from_addr))
        headers.add("To", str(to_addr))
        headers.add("Call-ID", call.call_id)
        headers.add("CSeq", f"{call.cseq} ACK")
        headers.add("User-Agent", self.user_agent_header)
        headers.set("Content-Length", "0")
        req = SIPRequest(method="ACK",
                         request_uri=str(call.remote_target or call.remote_uri),
                         headers=headers)
        await self.transport.send(req.encode(), account.server)

    async def _send_ack_for_failure(
        self, call: Call, resp: SIPResponse, dest: tuple[str, int]
    ) -> None:
        """ACK for non-2xx final responses must use the INVITE's branch."""
        if not call.invite_request:
            return
        via = call.invite_request.headers.get("Via") or ""
        from_ = call.invite_request.headers.get("From") or ""
        cid = call.call_id
        to_ = resp.headers.get("To") or call.invite_request.headers.get("To") or ""
        headers = Headers()
        headers.add("Via", via)
        headers.add("Max-Forwards", "70")
        headers.add("From", from_)
        headers.add("To", to_)
        headers.add("Call-ID", cid)
        headers.add("CSeq", f"{call.cseq} ACK")
        headers.add("User-Agent", self.user_agent_header)
        headers.set("Content-Length", "0")
        req = SIPRequest(method="ACK",
                         request_uri=str(call.remote_uri),
                         headers=headers)
        await self.transport.send(req.encode(), dest)

    async def _send_bye(self, call: Call) -> None:
        account = call.account
        call.cseq += 1
        from_addr = NameAddr(display=account.display,
                             uri=URI.parse(account.aor),
                             params={"tag": call.local_tag})
        to_params = {"tag": call.remote_tag} if call.remote_tag else {}
        to_addr = NameAddr(uri=call.remote_uri, params=to_params)

        async def do_send(auth_header: tuple[str, str] | None = None):
            extra = []
            if auth_header:
                extra.append(auth_header)
            req = self._build_request(
                "BYE", call.remote_target or call.remote_uri,
                account=account, call_id=call.call_id, cseq_num=call.cseq,
                from_addr=from_addr, to_addr=to_addr,
                extra_headers=extra,
            )
            return await self._send_and_wait(req, account.server,
                                             call.call_id, call.cseq)

        try:
            resp = await do_send()
            if resp.status_code in (401, 407):
                call.cseq += 1
                auth = self._build_auth_header_from_response(
                    resp, method="BYE",
                    uri=str(call.remote_target or call.remote_uri),
                    account=account)
                await do_send(auth)
        except asyncio.TimeoutError:
            pass

    async def _hangup_call(self, call: Call) -> None:
        if call.state == "answered":
            await self._send_bye(call)
        if call.rtp:
            await call.rtp.stop()
            call.rtp = None
        call.state = "ended"
        call._ended.set()
        call._answered.set()
        self._calls.pop(call.call_id, None)

    # ------------------------------------------------------------------
    # Incoming requests
    # ------------------------------------------------------------------
    async def _handle_incoming_invite(self, req: SIPRequest, source: tuple[str, int]) -> None:
        call_id = req.call_id or ""
        if call_id in self._calls:
            # re-INVITE — not supported; just answer 200 with same SDP for now.
            # For v0.1 we send 491 Request Pending.
            await self._respond(req, 491, "Request Pending", source)
            return

        # Send 100 Trying immediately.
        await self._respond(req, 100, "Trying", source)

        # Find the account for the request-URI.
        to_addr = NameAddr.parse(req.headers.get("To") or "")
        account = self._find_account_for(to_addr.uri)
        if account is None:
            await self._respond(req, 404, "Not Found", source)
            return

        call = Call(self, account, outbound=False)
        call.call_id = call_id
        call.cseq = (req.cseq or (1, ""))[0]
        call.invite_request = req
        call.source = source
        from_addr = NameAddr.parse(req.headers.get("From") or "")
        call.remote_tag = from_addr.params.get("tag", "")
        call.remote_uri = from_addr.uri
        contact_raw = req.headers.get("Contact")
        try:
            call.remote_target = NameAddr.parse(contact_raw).uri if contact_raw else call.remote_uri
        except Exception:
            call.remote_target = call.remote_uri

        if req.body:
            try:
                call.remote_sdp = SDPSession.parse(req.body)
            except Exception:
                await self._respond(req, 488, "Not Acceptable Here", source)
                return

        self._calls[call_id] = call

        # Ring & deliver to app.
        await self._respond(req, 180, "Ringing", source)
        call.state = "ringing"

        if self._incoming_call_cb is None:
            log.warning("no incoming-call handler; auto-rejecting")
            await self._respond(req, 603, "Decline", source)
            self._calls.pop(call_id, None)
            return
        try:
            await self._incoming_call_cb(call)
        except Exception as e:
            log.exception("incoming-call handler failed: %s", e)
            if call.state in ("ringing", "init"):
                await self._respond(req, 500, "Server Internal Error", source)
                self._calls.pop(call_id, None)

    async def _answer_call(self, call: Call) -> None:
        if call.invite_request is None:
            raise OpenSIPError("no INVITE to answer")
        req = call.invite_request
        # build SDP answer
        local_ip = self.local_addr[0]
        if local_ip in ("0.0.0.0", "::"):
            local_ip = guess_local_ip(call.account.server)
        rtp_port = pick_rtp_port_pair(host=local_ip,
                                      low=self.rtp_port_range[0],
                                      high=self.rtp_port_range[1])

        # negotiate codec
        offer = make_audio_offer(local_ip, rtp_port)
        chosen = pick_common_codec(offer, call.remote_sdp) if call.remote_sdp else None
        dest = call.source or call.account.server
        if chosen is None and call.remote_sdp:
            await self._respond(req, 488, "Not Acceptable Here", dest)
            self._calls.pop(call.call_id, None)
            return
        # narrow our answer to the chosen codec, but keep telephone-event
        # advertised if the peer offered it so DTMF still works.
        if chosen and call.remote_sdp:
            kept: list[Codec] = [chosen]
            for c in call.remote_sdp.media[0].codecs:
                if c.name.lower() == "telephone-event":
                    kept.append(Codec(
                        payload_type=c.payload_type, name=c.name,
                        clock_rate=c.clock_rate, channels=c.channels,
                        fmtp=c.fmtp or "0-15",
                    ))
                    break
            offer.media[0].codecs = kept
            offer.media[0].payload_types = [c.payload_type for c in kept]
        call.local_sdp = offer
        call.codec = chosen

        # Allocate RTP session.
        rtp = RTPSession(
            local_addr=(local_ip, rtp_port),
            payload_type=chosen.payload_type if chosen else 0,
            codec_name=chosen.name if chosen else "PCMU",
            dtmf_payload_type=_dtmf_pt_from_sdp(call.remote_sdp),
        )
        await rtp.start()
        if call.remote_sdp:
            remote_addr = (
                call.remote_sdp.media[0].connection[1]
                if call.remote_sdp.media[0].connection
                else call.remote_sdp.address,
                call.remote_sdp.media[0].port,
            )
            rtp.set_remote(remote_addr)
        call.rtp = rtp

        # 200 OK with SDP answer + To tag.
        resp = self._make_response(req, 200, "OK")
        # Tag the To header
        to_addr = NameAddr.parse(resp.headers.get("To") or "")
        to_addr.params["tag"] = call.local_tag
        resp.headers.set("To", str(to_addr))
        resp.headers.set("Contact", f"<{self._local_contact_uri(call.account)}>")
        resp.headers.set("Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS")
        resp.set_body(call.local_sdp.encode(), "application/sdp")
        await self.transport.send(resp.encode(), dest)

    async def _handle_incoming_ack(self, req: SIPRequest, source: tuple[str, int]) -> None:
        call = self._calls.get(req.call_id or "")
        if call and call.state == "ringing":
            call.state = "answered"
            call._answered.set()

    async def _handle_incoming_bye(self, req: SIPRequest, source: tuple[str, int]) -> None:
        call = self._calls.get(req.call_id or "")
        await self._respond(req, 200, "OK", source)
        if call:
            if call.rtp:
                await call.rtp.stop()
                call.rtp = None
            call.state = "ended"
            call._ended.set()
            call._answered.set()
            self._calls.pop(call.call_id, None)

    async def _handle_incoming_cancel(self, req: SIPRequest, source: tuple[str, int]) -> None:
        call = self._calls.get(req.call_id or "")
        await self._respond(req, 200, "OK", source)
        if call and call.state in ("init", "ringing"):
            # 487 to the original INVITE
            if call.invite_request:
                await self._respond(call.invite_request, 487,
                                    "Request Terminated", source)
            call.state = "ended"
            call._failed_reason = "canceled"
            call._answered.set()
            call._ended.set()
            self._calls.pop(call.call_id, None)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _find_account_for(self, uri: URI) -> Account | None:
        # The UA doesn't yet hold accounts directly; find via active calls /
        # registered accounts. For v0.1, accept any incoming call and use the
        # first registered account.
        for call in self._calls.values():
            if call.account.username == (uri.user or ""):
                return call.account
        # find any account from running registrations
        for acc in self._iter_known_accounts():
            if acc.username == (uri.user or ""):
                return acc
            if acc.domain == uri.host:
                return acc
        # fallback
        return next(iter(self._iter_known_accounts()), None)

    def _iter_known_accounts(self):
        seen: set[int] = set()
        for acc in self._accounts:
            if id(acc) not in seen:
                seen.add(id(acc))
                yield acc
        for c in self._calls.values():
            if id(c.account) not in seen:
                seen.add(id(c.account))
                yield c.account

    def _make_response(self, req: SIPRequest, code: int, reason: str) -> SIPResponse:
        h = Headers()
        for via in req.headers.get_all("Via"):
            h.add("Via", via)
        if "From" in req.headers:
            h.add("From", req.headers["From"])
        if "To" in req.headers:
            h.add("To", req.headers["To"])
        if "Call-ID" in req.headers:
            h.add("Call-ID", req.headers["Call-ID"])
        if "CSeq" in req.headers:
            h.add("CSeq", req.headers["CSeq"])
        for rr in req.headers.get_all("Record-Route"):
            h.add("Record-Route", rr)
        h.add("User-Agent", self.user_agent_header)
        h.set("Content-Length", "0")
        return SIPResponse(status_code=code, reason=reason, headers=h)

    async def _respond(self, req: SIPRequest, code: int, reason: str,
                       source: tuple[str, int]) -> None:
        resp = self._make_response(req, code, reason)
        await self.transport.send(resp.encode(), source)

    async def _send_and_wait(self, req: SIPRequest, dest: tuple[str, int],
                             call_id: str, cseq_num: int,
                             timeout: float = 32.0) -> SIPResponse:
        key = (call_id, cseq_num)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending_responses[key] = fut
        try:
            await self.transport.send(req.encode(), dest)
            return await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self._pending_responses.pop(key, None)

    def _build_auth_header_from_response(
        self,
        resp: SIPResponse,
        *,
        method: str,
        uri: str,
        account: Account,
        body: bytes = b"",
    ) -> tuple[str, str]:
        if resp.status_code == 407:
            chal_raw = resp.headers.get("Proxy-Authenticate")
            header_name = "Proxy-Authorization"
        else:
            chal_raw = resp.headers.get("WWW-Authenticate")
            header_name = "Authorization"
        if not chal_raw:
            raise AuthenticationError(
                f"{resp.status_code} without auth challenge header"
            )
        chal = Challenge.from_header(chal_raw)
        value = build_authorization(
            challenge=chal, method=method, uri=uri,
            username=account.username, password=account.password,
            body=body, proxy=(resp.status_code == 407),
        )
        return (header_name, value)


__all__ = ["Account", "Call", "UserAgent"]
