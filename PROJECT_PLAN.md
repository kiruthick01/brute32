# Brute32 — ESP32 All-in-One WiFi/BLE Pentest Tool — Project Plan

**Project name:** `Brute32` (repo slug suggestion: `brute32`)

Base reference: fork of risinek's `esp32-wifi-penetration-tool` (deauth, PMKID/handshake capture, PCAP/HCCAPX export, web UI on ESP-IDF). This plan is the spec to hand to Claude Code when you start building.

---

## 0. Scope & Intent

Personal, self-hosted red-team/pentest toolkit for **networks and devices you own or are explicitly authorized to test**. Hardware comes later; this phase is firmware architecture + software features, built so a display/buttons/SD/GPS module can be bolted on without a rewrite.

---

## 1. Hardware Target

- **Primary MCU:** ESP32-S3 (dual-core, more RAM/PSRAM, native USB, actively supported by newer ESP-IDF — better choice than classic ESP32 or S2 for this).
- **UI:** Small SPI TFT (e.g. ST7789 240x240/135) or OLED (SSD1306) + a handful of buttons/rotary encoder — Marauder-style standalone operation, no phone required. Build the display/input layer behind an abstraction so it's a no-op until hardware exists (headless web-UI-only mode works from day one).
- **Optional later:** microSD (logging), GPS module (UART, for wardriving tags), battery + charge circuit.

## 2. Framework

- **ESP-IDF 5.x** (current stable), not Arduino/PlatformIO. Keeps you close to the WiFi/BLE stack internals, which matters for raw 802.11 frame injection and BLE advertising — the original's biggest weakness is being frozen on IDF 4.1–4.4. Modernizing unlocks S3 support, newer WiFi driver fixes, and idf.py's improved build/monitor tooling.
- BLE features will use ESP-IDF's NimBLE stack (lighter than Bluedroid, better documented for S3).

## 3. Feature Set (all-in-one, phased so it's buildable incrementally)

### Phase 1 — Modernize the core (get a solid foundation first)
- Port original components to IDF 5.x; fix deprecated API calls.
- Clean up: proper component structure, Kconfig options, consistent error handling/logging.
- WiFi controller: scan, AP-mode, STA-mode, monitor mode toggling.
- Attacks: deauth (broadcast + targeted), PMKID capture, WPA/WPA2 handshake capture.
- Export: PCAP + HCCAPX (Hashcat-ready) to flash/SPIFFS, downloadable via web UI.
- Web UI: rebuild as a small SPA (served from flash), mobile-friendly, replaces the original's dated interface.
- **Deliverable:** working headless device, controlled entirely over its own AP + web UI.

### Phase 2 — Evil twin / rogue AP
- Cloneable AP (copy target SSID/channel/security banner).
- Captive portal with a credential-harvesting login page (for authorized phishing-awareness testing).
- Rogue AP + karma-style probe response handling.

### Phase 3 — BLE recon & spam
- BLE scanner (advertising packet capture, device fingerprinting).
- BLE spam/jamming demos (Apple/Android BLE spam, common in Flipper/Marauder-class tools) — flagged clearly as disruptive/for isolated test environments only.

### Phase 4 — Storage & wardriving
- microSD logging of captures (PCAP/HCCAPX + session metadata).
- GPS UART integration, tag captures with coordinates, export wardriving-format CSV/KML.

### Phase 5 — On-device UI
- Display driver abstraction (LVGL recommended — good ESP-IDF support, works headless-safe).
- Menu system mirroring the web UI's actions, button/encoder input handling.
- Falls into place last since it's pure hardware-dependent work you said you'll do later.

## 4. Proposed Repo Structure

```
brute32/
├── main/                     # app entry, orchestration
├── components/
│   ├── wifi_controller/       # scan/AP/STA/monitor mode
│   ├── ble_controller/        # NimBLE scan + spam
│   ├── attack_deauth/
│   ├── attack_pmkid_handshake/
│   ├── attack_evil_twin/
│   ├── frame_analyzer/        # 802.11 frame parsing
│   ├── serializers/           # PCAP / HCCAPX / KML / CSV writers
│   ├── storage/                # SPIFFS + SD abstraction
│   ├── gps/                    # UART GPS parser (later)
│   ├── display/                 # LVGL + driver abstraction (later, no-op until hw exists)
│   └── webserver/              # HTTP server + SPA assets
├── web-ui/                    # source for the SPA (built, then embedded into flash image)
├── doc/                        # attack theory, architecture diagrams, wiring diagrams (later)
├── CMakeLists.txt
├── sdkconfig.defaults
├── LICENSE
└── README.md
```

## 5. Legal / Ethical Framing (prominent in README)

- Clear statement: for use only on networks/devices you own or have explicit written authorization to test; unauthorized use of deauth/rogue-AP/credential-harvesting features against others' networks is illegal in most jurisdictions.
- License: MIT or GPLv3 with an added "Acceptable Use" section (same pattern risinek's original and most ESP32 Marauder forks use) rather than inventing a custom restrictive license — keeps it a normal open-source repo while making intent explicit.
- Optional: a short THREAT_MODEL.md documenting what each attack does and its real-world impact, useful both as documentation and as evidence of educational intent.

## 6. Suggested Build Order for the Claude Code session

1. `idf.py create-project`, set target `esp32s3`, bring in Phase 1 components one at a time, get deauth + PMKID capture working and verified against your own test AP.
2. Rebuild the web UI.
3. Add evil twin (Phase 2).
4. Add BLE (Phase 3).
5. Add storage/GPS (Phase 4) once you're ready to wire up hardware.
6. Add display/LVGL (Phase 5) last, once the physical build exists.

Start each phase by asking Claude Code to write/port one component at a time and flash-test on real hardware before moving to the next — don't let multiple untested attack modules stack up.
