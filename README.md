<div align="center">

```
    ____  ____  __  ______________  ________
   / __ )/ __ \/ / / /_  __/ ____/ /__  /__ \
  / __  / /_/ / / / / / / / __/     /_ <__/ /
 / /_/ / _, _/ /_/ / / / / /___   ___/ / __/
/_____/_/ |_|\____/ /_/ /_____/  /____/____/
```

**ESP32-S3 Wireless Attack Platform**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-5.3.x-e7352c.svg?logo=espressif&logoColor=white)](https://github.com/espressif/esp-idf)
[![Target](https://img.shields.io/badge/target-ESP32--S3-e7352c.svg?logo=espressif&logoColor=white)](#build)
[![Phase](https://img.shields.io/badge/phase-1%20of%205-yellow.svg)](#status)
[![Build](https://img.shields.io/badge/idf.py%20build-passing-brightgreen.svg)](#build)
[![Use](https://img.shields.io/badge/use-authorized%20only-critical.svg)](#scope-of-use)

</div>

---

`brute32` is a from-scratch rebuild of the ESP32 802.11/BLE attack-surface toolkit lineage (risinek's `esp32-wifi-penetration-tool`, ESP32 Marauder) — retargeted at ESP32-S3, rebased on ESP-IDF 5.3.x, and restructured as independent, testable components instead of one webserver-coupled blob. Built for authorized wireless security assessment and protocol research on hardware and networks you own or are cleared to test.

### Contents

- [Status](#status)
- [Architecture](#architecture)
- [Console commands](#console-commands-phase-1)
- [Build](#build)
- [Scope of use](#scope-of-use)
- [Roadmap](#roadmap)

---

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Core: WiFi ctl, frame analysis, PCAP/HCCAPX serialization, deauth, PMKID/handshake capture, SPIFFS, console REPL | `idf.py build` clean on IDF 5.3.2 / `esp32s3`. Hardware validation in progress. |
| 2 | Evil twin AP + captive portal | Not started |
| 3 | BLE recon + advertising-layer attacks | Not started |
| 4 | microSD logging + GPS-tagged capture (wardriving) | Not started |
| 5 | On-device display + button/encoder UI | Not started |

No web UI yet by design — Phase 1 is driven entirely through a serial console, so every primitive is verified in isolation before anything gets wrapped in a UI layer.

---

## Architecture

```
brute32/
├── main/                        orchestration + esp_console REPL
├── components/
│   ├── wifi_controller/         AP/STA lifecycle, channel + MAC control,
│   │                            AP scan, promiscuous-mode frame sniffer
│   ├── frame_analyzer/          802.11 + EAPoL parsing, PMKID/handshake
│   │                            detection over the ESP event loop
│   ├── serializers/             PCAP + HCCAPX buffer writers
│   ├── attack_deauth/           broadcast + targeted deauth via raw
│   │                            802.11 frame injection
│   ├── attack_pmkid_handshake/  passive PMKID + WPA/WPA2 4-way capture
│   └── storage/                 SPIFFS wrapper, custom partition table
├── partitions.csv
├── sdkconfig.defaults
└── CMakeLists.txt
```

Each attack/capture component exposes a typed result API — no shared global state, no coupling to a webserver that doesn't exist yet. That's a deliberate departure from the upstream project this is based on, where every module wrote status strings into a struct the webserver polled.

<details>
<summary><strong>Notable implementation details</strong></summary>
<br>

- **Raw frame injection** (`attack_deauth`) uses the `wsl_bypasser` technique — overriding `ieee80211_raw_frame_sanity_check` to push handcrafted 802.11 management frames past the stock `libnet80211.a` blob's validation. This is undocumented-internals territory; behavior is pinned to IDF 5.3.2 on `esp32s3` and re-verified on every toolchain bump.
- **PMKID capture** pulls the PMKID directly from the first EAPOL message of the 4-way handshake (RSN IE, no deauth required) — the same technique documented by hashcat/atom for the original clientless PMKID attack.
- **Handshake capture** is fully passive: sniffs EAPOL M1–M4 off natural client reassociation. Pair with your own deauth call if you need to force a handshake on a network you control.
- **Serialization** targets are file formats, not display formats — PCAP for Wireshark analysis, HCCAPX for direct `hashcat -m 22000` input.

</details>

---

## Console commands (Phase 1)

| Command | Description |
|---|---|
| `scan` | Active AP scan, populates target list (index into it with the commands below) |
| `deauth <index> [sta_mac] [period_sec]` | Deauth attack against `scan` result `<index>` — broadcast (all clients) if `sta_mac` omitted, targeted otherwise. Resends every `period_sec` (default 1) |
| `deauth_stop` | Stop the running deauth attack |
| `pmkid <index>` | Passive PMKID capture against `scan` result `<index>` |
| `pmkid_stop` | Stop the running PMKID capture |
| `handshake <index>` | Passive WPA/WPA2 handshake capture against `scan` result `<index>` |
| `handshake_stop` | Stop the running handshake capture |
| `status` | Current PMKID/handshake capture status and buffer size |
| `save <name>` | Flush current capture buffer to SPIFFS as `<name>.pcap` / `<name>.hccapx` (whichever has data) |
| `fs_list` | List captured files in flash storage |

---

## Build

```sh
. $IDF_PATH/export.sh
idf.py set-target esp32s3
idf.py build
idf.py -p <PORT> flash monitor
```

Builds clean against ESP-IDF `v5.3.2` targeting `esp32s3`. `sdkconfig.defaults` is set for a 16MB flash / 8MB octal PSRAM module (e.g. ESP32-S3-N16R8) — adjust `CONFIG_ESPTOOLPY_FLASHSIZE` and the `SPIRAM_*` options under `idf.py menuconfig` if your board differs. `partitions.csv` reserves a 1MB SPIFFS region for capture storage.

---

## Scope of use

> [!WARNING]
> This is a personal research and authorized-pentest tool. It is built to run against wireless infrastructure you own, or infrastructure you hold explicit written authorization to test. Deauthentication, rogue-AP, and credential-capture techniques implemented here are disruptive and, in most jurisdictions, illegal to run against networks without that authorization. This project does not grant permission to test anything — that authorization is yours to obtain and yours to keep records of.

Released under the [MIT License](LICENSE) with the above use restriction as a condition of use, not a suggestion.

---

## Roadmap

See [`PROJECT_PLAN.md`](PROJECT_PLAN.md) for the full phased build-out — evil twin/captive portal, BLE scanning + advertising attacks, SD + GPS wardriving support, and the on-device LVGL display/button UI that eventually turns this into standalone hardware rather than a serial-tethered board.
