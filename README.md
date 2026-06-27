# opensip

[![PyPI](https://img.shields.io/pypi/v/opensip)](https://pypi.org/project/opensip/)
[![Python](https://img.shields.io/pypi/pyversions/opensip)](https://pypi.org/project/opensip/)
[![License](https://img.shields.io/pypi/l/opensip)](https://github.com/artanergin44-collab/opensip/blob/main/LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange)](#bilinen-s%C4%B1n%C4%B1rlamalar)

**Saf-Python, asyncio tabanlı SIP/RTP user-agent kütüphanesi.** UAC + UAS, REGISTER, HTTP Digest auth, G.711 ses kodek'i, opsiyonel mikrofon/hoparlör köprüsü — sıfır C bağımlılığı, ~33 KB wheel.

```bash
pip install opensip          # sinyalleşme + RTP (numpy varsa hızlandırma)
pip install "opensip[audio]" # + mic/speaker köprüsü (sounddevice + numpy)
```

> ⚠️ **Erken alfa.** Gerçek bir Türk bulut-PBX provider'ı (netsantral.com) üzerinden uçtan uca **iki yönlü ses** ile doğrulandı. Yine de RFC 3261'in birkaç önemli parçası eksik — production'a almadan önce [Bilinen sınırlamalar](#bilinen-s%C4%B1n%C4%B1rlamalar) bölümünü okuyun.

## Özellikler

- 🎯 **Saf Python**, sıfır C bağımlılığı (audio extra hariç)
- ⚡ **asyncio** — tek event loop'ta binlerce eşzamanlı dialog
- 📞 **UAC + UAS** — hem arama yap hem de cevap ver
- 🔐 **HTTP Digest auth** — MD5, MD5-sess, SHA-256, qop=auth (RFC 7616)
- 🎙️ **G.711 PCMU/PCMA** — numpy varsa vektörize, 20 ms frame başına ~1 µs
- 🔄 **OPTIONS keepalive** — provider'ın "alive?" pingini otomatik 200 OK
- 🎧 **Mic/speaker köprüsü** — `sounddevice` ile sistem ses cihazlarına bağla
- 🧱 **Jitter buffer** — reorder + gap-fill (silence) + RFC 3550 §A.8 jitter ölçümü
- ☎️ **DTMF her iki yönde** — `send_dtmf()` (RFC 4733) gönderim, `on_dtmf` callback ile alım
- 📊 **RTP istatistikleri** — `RTPSession.stats` ile paket/byte sayaçları + jitter
- 📦 **Tip ipuçları her yerde** — `py.typed` paketlenmiş

## Sürüm notları

### 0.2.0 (yeni)
- **Jitter buffer** — `RTPSession`'a varsayılan açık (`jitter_ms=60`). Sıra dışı paketleri yeniden sıralar, kayıp frame yerine sessizlik koyar, `jitter_ms=0` ile devre dışı bırakılabilir.
- **`JitterBuffer.recommended_target_ms()`** — RFC 3550 §A.8 EWMA ile ağ koşullarına göre hedef derinlik önerir.
- **DTMF alımı (RFC 4733)** — `RTPSession.on_dtmf` / `Call.on_dtmf` callback; sürdürme + 3 redundant end-packet otomatik dedup.
- **`RTPSession.stats`** — `packets_sent/recv`, `bytes_sent/recv`, `dtmf_recv` + iç içe jitter sub-stats.

## Hızlı başlangıç

### Giden arama

```python
import asyncio
from opensip import UserAgent, Account

async def main():
    ua = UserAgent(local_addr=("0.0.0.0", 5060))
    await ua.start()

    acc = Account(
        username="alice",
        domain="sip.example.com",
        password="s3cret",
        server=("sip.example.com", 5060),
    )
    await ua.register(acc)

    call = await ua.invite(acc, "sip:bob@sip.example.com")
    await call.wait_answered()
    await asyncio.sleep(10)
    await call.hangup()

    await ua.stop()

asyncio.run(main())
```

### Gelen arama

```python
import asyncio
from opensip import UserAgent, Account

async def main():
    ua = UserAgent(local_addr=("0.0.0.0", 5060))

    @ua.on_incoming_call
    async def handle(call):
        await call.answer()
        await call.wait_ended()

    await ua.start()
    acc = Account(username="alice", domain="sip.example.com",
                  password="s3cret", server=("sip.example.com", 5060))
    await ua.register(acc)
    await asyncio.Event().wait()  # sonsuza kadar bekle

asyncio.run(main())
```

### Mikrofon ↔ uzak taraf köprüsü (audio extras ile)

```python
from opensip.audio import AudioBridge

# ... yukarıdaki örnekteki gibi call'u kur ...

bridge = AudioBridge(sample_rate=8000)
bridge.start()
call.on_pcm(bridge.feed_speaker)         # uzak taraf → hoparlör

async def pump_mic():
    while call.is_active:
        pcm = await bridge.read_microphone()
        call.write_pcm(pcm)              # mikrofon → uzak taraf

asyncio.create_task(pump_mic())
```

Çalışan örnekler: [`examples/make_call.py`](examples/make_call.py), [`examples/receive_call.py`](examples/receive_call.py).

## API özeti

```python
from opensip import UserAgent, Account, Call
```

**`UserAgent`** — top-level facade
| Yöntem | Açıklama |
|---|---|
| `await ua.start()` / `stop()` | Transport'u aç / kapat |
| `await ua.register(acc)` | REGISTER + otomatik yenileme |
| `await ua.unregister(acc)` | `Expires: 0` REGISTER |
| `await ua.invite(acc, target)` → `Call` | Giden çağrı kur |
| `@ua.on_incoming_call` | Gelen INVITE handler decorator |

**`Call`** — bir SIP dialog'u
| Yöntem / property | Açıklama |
|---|---|
| `await call.wait_answered(timeout=None)` | 200 OK'i bekle |
| `await call.wait_ended()` | BYE'ı bekle |
| `await call.answer()` | UAS — gelen çağrıyı cevapla |
| `await call.hangup()` | BYE gönder, RTP kapat |
| `call.write_pcm(bytes)` | Uzak tarafa 16-bit PCM gönder |
| `call.on_pcm(callback)` | Gelen PCM için handler |
| `call.is_active` | Dialog `"answered"` durumunda mı |
| `call.codec` | Anlaşılan codec (`Codec` nesnesi) |

**`AudioBridge`** (`opensip[audio]` extras)
| Yöntem | Açıklama |
|---|---|
| `bridge.start()` / `stop()` | Mikrofon + hoparlör stream'leri |
| `await bridge.read_microphone()` | Bir frame PCM oku |
| `bridge.feed_speaker(bytes)` | Hoparlöre PCM gönder |

## Performans

G.711 PCMU/PCMA hot path, numpy varsa vektörize LUT lookup'a düşer. Apple M-series üzerinde, 8 kHz × 20 ms × 16-bit frame için:

| İşlem | Saf-Python | numpy | Hızlanma |
|---|---:|---:|---:|
| PCMU encode | 13.1 µs/frame | 1.0 µs/frame | **13.6×** |
| PCMU decode | 25.8 µs/frame | 1.0 µs/frame | **25.3×** |
| PCMA encode | 12.4 µs/frame | 1.0 µs/frame | **12.7×** |
| PCMA decode | 25.6 µs/frame | 1.0 µs/frame | **24.4×** |

20 ms ptime bütçesinin **%0.005**'i — binlerce paralel çağrıda codec CPU yükü ihmal edilebilir. Çıktının bit-exact'liği 65,536 PCM değerinin tümü üzerinde doğrulanmıştır.

Yeniden üretmek için:

```bash
python tests/bench_codecs.py
```

## Doğrulanmış provider'lar

| Provider | Sinyalleşme | İki yönlü ses | Notlar |
|---|:---:|:---:|---|
| **netsantral.com** | ✅ | ✅ | Symmetric-RTP / SBC NAT handling sağlıyor |
| sip2sip.info | ⚠️ test edilmedi | — | Açık-kayıt test provider'ı, deneyebilirsiniz |
| Twilio SIP trunking (TLS) | ❌ | — | TLS-only; opensip henüz TLS desteklemiyor |
| Yerel Asterisk / FreeSWITCH | 🟢 beklenen | 🟢 beklenen | LAN'da NAT olmadan çalışmalı |

## Mimari

```
opensip/
├── message.py     # SIP request/response parser + serializer (RFC 3261 §7-§20)
├── headers.py     # URI, NameAddr, Via — compact form, IPv6, quoted params
├── auth.py        # HTTP Digest (MD5/MD5-sess/SHA-256, qop=auth)
├── sdp.py         # SDP offer/answer (RFC 4566), audio m=line + codec seçimi
├── transport.py   # asyncio UDP transport
├── ua.py          # UserAgent — UAC + UAS facade, dialog state inline
├── rtp.py         # RTP packetization (RFC 3550) + 20 ms ptime sender loop
├── codecs.py      # G.711 µ-law / A-law — numpy hot path + pure-Python fallback
├── audio.py       # sounddevice wrapper (opsiyonel)
├── utils.py       # branch/tag/Call-ID üreteçleri, IP keşfi
└── exceptions.py  # Hata hiyerarşisi
```

## Bilinen sınırlamalar

`opensip` hâlâ erken alfa bir UA: gerçek bir provider ile çağrı yapar ama RFC 3261'in birkaç önemli parçası **henüz yok**. Telefon altyapısı kurmadan önce farkında olun.

- **Transaction katmanı yok** (RFC 3261 §17). UDP retransmission timer'ları (Timer A–K) yok — paket düşerse istek timeout'a düşer. LAN / kayıpsız ağda fark edilmez; internet üzerinden kaybedilen ilk INVITE'ı tekrar göndermez.
- **Dialog state machine sınırlı.** Re-INVITE (hold/resume), UPDATE, target refresh çalışmaz; route set INVITE/BYE/ACK'te kullanılmaz — uzun proxy zincirleri kırılır.
- **NAT handling client-side yok.** SDP `c=` satırına LAN IP yazılır; iki yönlü RTP yalnızca provider symmetric-RTP / SBC NAT handling yapıyorsa çalışır (netsantral yapıyor, çoğu yapmaz). rport/received Contact'a yansıtılmaz, STUN/ICE yok.
- **Yalnızca UDP.** TCP ve TLS yok; TLS-only provider'lar (bazı Twilio konfigürasyonları) için kullanılamaz.
- **RTCP yok.** RTP istatistikleri ve jitter ölçümü var, ancak SR/RR paketleri ve RTCP tabanlı raporlama henüz yok.
- **Jitter buffer adaptif değil.** Sabit hedef derinlikle reorder + gap-fill yapar; otomatik retune / drift management henüz yok.
- **DTMF kapsamı sınırlı.** RFC 4733 giriş/çıkış temel akışı var, ancak SIP INFO veya daha gelişmiş interop senaryoları henüz yok.
- **Codec sınırlı.** PCMU + PCMA + telephone-event (gönderme yok). Opus / G.722 / G.729 yok.
- **Authorization re-use yok.** Her INVITE/BYE'da yeniden challenge — küçük gecikme katar.

## Karşılaştırma

| | **opensip** | aiosip | baresip | pjproject |
|---|:---:|:---:|:---:|:---:|
| Dil | Pure Python | Pure Python | C | C/C++ |
| asyncio | ✅ | ✅ | ❌ | ❌ |
| Mic/speaker bridge | ✅ | ❌ | ✅ | ✅ |
| Transaction layer | ❌ (roadmap) | ❌ | ✅ | ✅ |
| NAT (ICE/STUN) | ❌ (roadmap) | ❌ | ✅ | ✅ |
| TLS / SRTP | ❌ (roadmap) | ❌ | ✅ | ✅ |
| Video | ❌ | ❌ | ✅ | ✅ |
| Wheel boyutu | ~33 KB | ~30 KB | — | — |
| Kullanım amacı | Python-native scripting, prototip, embedded automation | İlkel araştırma | Production CLI/embedded | Carrier-grade SDK |

opensip "küçük, Python-native, hack'lemesi kolay" yönünde bir niş tutuyor. Carrier-grade telefon altyapısı için **pjproject** veya **baresip + Python binding** önerilir.

## Yol haritası

- **Faz 1 — sağlamlaştırma:** transaction katmanı (RFC 3261 §17), tam dialog state machine, rport/received NAT, TCP transport, RTCP SR/RR, jitter buffer, DTMF (RFC 2833 in/out)
- **Faz 2 — özellik:** TLS + SRTP, ICE-lite (RFC 8445), Opus + G.722, MESSAGE/SUBSCRIBE/NOTIFY/REFER, re-INVITE/hold, video iskeleti
- **Faz 3 — test + perf:** Docker'da Asterisk/Kamailio/FreeSWITCH entegrasyon testleri, parser fuzzing (hypothesis), zero-copy parsing

Detaylı önceliklendirme ve durum: [issue tracker](https://github.com/artanergin44-collab/opensip/issues).

## Geliştirme

```bash
git clone https://github.com/artanergin44-collab/opensip.git
cd opensip
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev,audio]"
.venv/bin/pytest -v          # 17 unit + 1 loopback testi
.venv/bin/ruff check src tests
```

Python 3.10+ gerekiyor. macOS Homebrew kullanıyorsan: `brew install python@3.12`.

**G.711 mikrobenchmark:**

```bash
.venv/bin/python tests/bench_codecs.py
```

**Canlı arama testi:** `examples/.env.example`'ı kopyalayıp credentials gir, ardından:

```bash
LOG_LEVEL=DEBUG .venv/bin/python examples/make_call.py
```

## Katkı

PR'lar memnuniyetle. Açmadan önce:

1. Public API değişikliği yapıyorsanız önce bir issue açın
2. `pytest` ve `ruff check src tests` yeşil olmalı
3. Yeni özelliklere unit test eklenmeli — özellikle parser/codec/auth modüllerinde
4. Commit mesajları konvansiyonel format (`feat:`, `fix:`, `docs:`) tercih edilir ama zorunlu değil

## Lisans

[MIT](LICENSE) © artan

## Teşekkürler

- [numpy](https://numpy.org/) — G.711 vektörize hot path
- [sounddevice](https://python-sounddevice.readthedocs.io/) + PortAudio — mikrofon/hoparlör erişimi
- [hatchling](https://hatch.pypa.io/) — build sistemi
- IETF RFC 3261, 3550, 4566, 7616 yazarları
