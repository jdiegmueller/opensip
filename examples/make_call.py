"""Place an outgoing SIP call using credentials from .env.

Usage:
    cp examples/.env.example examples/.env   # then edit
    python examples/make_call.py

With `pip install "opensip[audio]"`, microphone + speaker are bridged to the
call automatically. Without the audio extras the call still connects but
sends silence and discards incoming RTP.

CALL_TARGET can be a full SIP URI ("sip:bob@host") or a bare phone number
("05467474444" / "+905467474444") — in the latter case it's wrapped using
SIP_SERVER as the host. STATS_LOG_INTERVAL_S>0 enables periodic logging of
RTP/jitter counters. CALL_DURATION_S=0 keeps the call alive until Ctrl+C
(SIGINT triggers a graceful BYE).
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path

# Make sibling `src/opensip` importable when running straight from the repo.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from _env import load_env  # noqa: E402
from opensip import Account, UserAgent  # noqa: E402

load_env()
logging.basicConfig(level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
                    format="%(asctime)s [%(name)s] %(message)s")
log = logging.getLogger("make_call")


def env(key: str, default: str | None = None, *, required: bool = False) -> str:
    v = os.environ.get(key, default)
    if required and not v:
        print(f"missing env var: {key}", file=sys.stderr)
        sys.exit(2)
    return v or ""


def normalise_target(target: str, sip_server: str) -> str:
    """Accept bare digits or a full sip: URI; return a full URI."""
    t = target.strip()
    if t.startswith(("sip:", "sips:")):
        return t
    digits = t.lstrip("+").replace(" ", "")
    if digits.isdigit() and sip_server:
        return f"sip:{digits}@{sip_server}"
    return t  # let the URI parser complain if it's malformed


async def stats_logger(call, interval_s: float) -> None:
    """Log RTPSession.stats periodically while the call is active."""
    if interval_s <= 0:
        return
    try:
        while call.is_active:
            await asyncio.sleep(interval_s)
            if not call.rtp:
                continue
            s = call.rtp.stats
            jb = s.get("jitter", {})
            log.info(
                "stats: pkts %d↑/%d↓  bytes %d↑/%d↓  dtmf↓%d  "
                "jitter=%.1fms (n=%d, lost=%d, late=%d, buf=%d, primed=%s)",
                s["packets_sent"], s["packets_recv"],
                s["bytes_sent"], s["bytes_recv"], s["dtmf_recv"],
                jb.get("jitter_ms", 0.0), jb.get("jitter_samples", 0),
                jb.get("lost", 0), jb.get("late", 0),
                jb.get("buffered_frames", 0),
                call.rtp._jitter.primed if call.rtp._jitter else "n/a",
            )
    except asyncio.CancelledError:
        return


async def main() -> int:
    server = env("SIP_SERVER", required=True)
    port = int(env("SIP_PORT", "5060"))
    username = env("SIP_USERNAME", required=True)
    password = env("SIP_PASSWORD", required=True)
    domain = env("SIP_DOMAIN", server)
    local_port = int(env("LOCAL_SIP_PORT", "5060"))
    raw_target = env("CALL_TARGET", required=True)
    target = normalise_target(raw_target, server)
    duration_s = float(env("CALL_DURATION_S", "30"))
    stats_interval_s = float(env("STATS_LOG_INTERVAL_S", "5"))

    ua = UserAgent(local_addr=("0.0.0.0", local_port))
    await ua.start()
    print(f"SIP UA listening on {ua.local_addr[0]}:{ua.local_addr[1]}")

    account = Account(
        username=username,
        domain=domain,
        password=password,
        server=(server, port),
    )

    print(f"REGISTER → {server}:{port} as {account.aor}")
    await ua.register(account)
    print("registered.")

    if target != raw_target:
        print(f"target normalised: {raw_target} → {target}")
    print(f"INVITE → {target}")
    call = await ua.invite(account, target)

    try:
        await call.wait_answered(timeout=40)
    except Exception as e:
        print(f"call setup failed: {e}")
        await ua.stop()
        return 1

    print(f"call answered (codec={call.codec.name if call.codec else '?'})")

    # DTMF inbound logger — useful for IVR menus / DTMF echo.
    call.on_dtmf(lambda d: log.info("DTMF ← %s", d))

    bridge = None
    try:
        from opensip.audio import AudioBridge  # type: ignore
        bridge = AudioBridge(sample_rate=8000)
        bridge.start()
        call.on_pcm(bridge.feed_speaker)
        print("audio bridge: mic→remote, remote→speaker")
    except Exception as e:
        print(f"audio bridge disabled: {e}")

    # Ctrl+C → graceful BYE
    shutdown = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown.set)
        except (NotImplementedError, RuntimeError):
            pass  # Windows / no main thread

    if duration_s > 0:
        print(f"konuşma penceresi: {duration_s:.0f} sn (CALL_DURATION_S env ile değiştir; 0 = sınırsız)")
    else:
        print("sınırsız mod — Ctrl+C ile BYE gönderilir")
    if stats_interval_s > 0:
        print(f"stats her {stats_interval_s:.0f} sn'de bir loglanacak")

    try:
        async def pump_mic():
            if not bridge:
                return
            while call.is_active:
                pcm = await bridge.read_microphone()
                call.write_pcm(pcm)

        mic_task = asyncio.create_task(pump_mic())
        stats_task = asyncio.create_task(stats_logger(call, stats_interval_s))
        ended_task = asyncio.create_task(call.wait_ended())
        shutdown_task = asyncio.create_task(shutdown.wait())

        waiters = [ended_task, shutdown_task]
        timeout = duration_s if duration_s > 0 else None
        done, _pending = await asyncio.wait(
            waiters, timeout=timeout, return_when=asyncio.FIRST_COMPLETED,
        )
        if shutdown_task in done:
            print("\nshutdown signal → hanging up")
        elif ended_task in done:
            print("remote ended the call")
        else:
            print(f"{duration_s:.0f} sn doldu → hanging up")

        mic_task.cancel()
        stats_task.cancel()
        for t in (mic_task, stats_task):
            try:
                await t
            except asyncio.CancelledError:
                pass
    finally:
        try:
            await call.hangup()
        except Exception as e:
            log.debug("hangup error: %s", e)
        if bridge:
            bridge.stop()
        # final stats dump
        if call.rtp:
            print(f"final stats: {call.rtp.stats}")
        await ua.stop()
    print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
