"""Tests for RTPSession.stats counters."""

import struct

from opensip.rtp import DTMF_DEFAULT_PT, RTPPacket, RTPSession


class _FakeTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        self.sent.append((data, addr))


def _dtmf_payload(event: int, end: bool) -> bytes:
    return struct.pack("!BBH", event, (0x80 if end else 0) | 10, 160)


async def _make_session(*, jitter_ms: int = 60) -> RTPSession:
    return RTPSession(
        local_addr=("127.0.0.1", 0), payload_type=0, jitter_ms=jitter_ms,
    )


async def test_stats_start_zero():
    sess = await _make_session()
    s = sess.stats
    assert s["packets_sent"] == 0
    assert s["packets_recv"] == 0
    assert s["bytes_sent"] == 0
    assert s["bytes_recv"] == 0
    assert s["dtmf_recv"] == 0
    assert s["jitter"]["received"] == 0


async def test_recv_counters_grow_with_audio_packet():
    sess = await _make_session()
    pkt = RTPPacket(
        payload_type=0, sequence=1, timestamp=160,
        ssrc=1, payload=b"\xff" * 160,
    )
    wire = pkt.pack()
    sess._on_datagram(wire, ("127.0.0.1", 9000))
    s = sess.stats
    assert s["packets_recv"] == 1
    assert s["bytes_recv"] == len(wire)
    # audio passed into jitter buffer, not played yet
    assert s["jitter"]["received"] == 1


async def test_dtmf_recv_counter():
    sess = await _make_session()
    pkt = RTPPacket(
        payload_type=DTMF_DEFAULT_PT, sequence=1, timestamp=500,
        ssrc=1, payload=_dtmf_payload(3, end=True),
    )
    wire = pkt.pack()
    sess._on_datagram(wire, ("127.0.0.1", 9000))
    sess._on_datagram(wire, ("127.0.0.1", 9000))  # dedup'd
    s = sess.stats
    assert s["dtmf_recv"] == 1
    assert s["packets_recv"] == 2  # raw datagrams still both count


async def test_send_counters_via_fake_transport():
    sess = await _make_session()
    sess._transport = _FakeTransport()  # type: ignore[assignment]
    sess.set_remote(("127.0.0.1", 1234))
    sess._emit_packet(b"\x00\x00" * 160)
    sess._emit_packet(b"\x00\x00" * 160)
    s = sess.stats
    assert s["packets_sent"] == 2
    assert s["bytes_sent"] > 0


async def test_stats_omits_jitter_when_disabled():
    sess = await _make_session(jitter_ms=0)
    assert "jitter" not in sess.stats
