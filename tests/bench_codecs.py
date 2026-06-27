from __future__ import annotations

import sys
import statistics
import struct
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from opensip.codecs import pcm_to_alaw, pcm_to_ulaw, alaw_to_pcm, ulaw_to_pcm


FRAME_SAMPLES = 160
ROUNDS = 20000


def make_frame() -> bytes:
    pcm = []
    for i in range(FRAME_SAMPLES):
        sample = ((i * 211) % 65536) - 32768
        pcm.append(sample)
    return struct.pack("<" + "h" * FRAME_SAMPLES, *pcm)


def bench(label: str, fn, payload: bytes) -> float:
    samples = []
    for _ in range(5):
        start = time.perf_counter()
        for _ in range(ROUNDS):
            fn(payload)
        elapsed = time.perf_counter() - start
        samples.append((elapsed / ROUNDS) * 1_000_000)
    us = statistics.mean(samples)
    print(f"{label:<12} {us:8.3f} us/frame")
    return us


def main() -> None:
    pcm = make_frame()
    ulaw = pcm_to_ulaw(pcm)
    alaw = pcm_to_alaw(pcm)

    if len(ulaw_to_pcm(ulaw)) != len(pcm):
        raise SystemExit("ulaw roundtrip length mismatch")
    if len(alaw_to_pcm(alaw)) != len(pcm):
        raise SystemExit("alaw roundtrip length mismatch")

    print(f"frame: {FRAME_SAMPLES} samples / {len(pcm)} bytes PCM")
    bench("PCMU encode", pcm_to_ulaw, pcm)
    bench("PCMU decode", ulaw_to_pcm, ulaw)
    bench("PCMA encode", pcm_to_alaw, pcm)
    bench("PCMA decode", alaw_to_pcm, alaw)


if __name__ == "__main__":
    main()
