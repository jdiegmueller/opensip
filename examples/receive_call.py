"""Register with a SIP server and answer any incoming call.

Usage:
    cp examples/.env.example examples/.env   # then edit
    python examples/receive_call.py

With `pip install "opensip[audio]"`, microphone + speaker are bridged.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from _env import load_env  # noqa: E402
from opensip import Account, Call, UserAgent  # noqa: E402

load_env()
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(name)s] %(message)s")


def env(key: str, default: str | None = None, *, required: bool = False) -> str:
    v = os.environ.get(key, default)
    if required and not v:
        print(f"missing env var: {key}", file=sys.stderr)
        sys.exit(2)
    return v or ""


async def main() -> int:
    server = env("SIP_SERVER", required=True)
    port = int(env("SIP_PORT", "5060"))
    username = env("SIP_USERNAME", required=True)
    password = env("SIP_PASSWORD", required=True)
    domain = env("SIP_DOMAIN", server)
    local_port = int(env("LOCAL_SIP_PORT", "5060"))

    ua = UserAgent(local_addr=("0.0.0.0", local_port))

    @ua.on_incoming_call
    async def handle(call: Call) -> None:
        print(f"incoming call from {call.remote_uri}")
        await call.answer()
        print("answered.")
        bridge = None
        try:
            from opensip.audio import AudioBridge  # type: ignore
            bridge = AudioBridge(sample_rate=8000)
            bridge.start()
            call.on_pcm(bridge.feed_speaker)
            print("audio bridge active.")

            async def pump_mic():
                while call.is_active:
                    pcm = await bridge.read_microphone()
                    call.write_pcm(pcm)

            mic_task = asyncio.create_task(pump_mic())
            try:
                await call.wait_ended()
            finally:
                mic_task.cancel()
        except Exception as e:
            print(f"audio bridge unavailable: {e}")
            await call.wait_ended()
        finally:
            if bridge:
                bridge.stop()
            print("call ended.")

    await ua.start()
    print(f"SIP UA listening on {ua.local_addr[0]}:{ua.local_addr[1]}")

    account = Account(
        username=username, domain=domain, password=password,
        server=(server, port),
    )
    await ua.register(account)
    print(f"registered as {account.aor}; waiting for calls. Ctrl-C to quit.")

    stop = asyncio.Event()
    try:
        await stop.wait()
    except KeyboardInterrupt:
        pass
    finally:
        await ua.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(0)
