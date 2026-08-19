# Dev Log

Rough running notes, not polished docs. Newest entry on top.

---

## 2026-08-19

Phase 1 build stood up from scratch and taken all the way to real hardware.

**Toolchain / repo setup**
- ESP-IDF v5.3.2 cloned locally (esp32s3 target only), cmake/ninja/dfu-util pulled in via brew (weren't installed).
- Ported core of risinek's `esp32-wifi-penetration-tool` to IDF 5.x: `wifi_controller`, `frame_analyzer`, `serializers` (pcap+hccapx), `attack_deauth` (+ `wsl_bypasser` raw-frame injection), `attack_pmkid_handshake`, `storage` (SPIFFS). No web UI yet — console REPL (`esp_console`) is the control surface for now.
- Fixed a handful of latent bugs while porting: filter-mask `else if` chain that silently dropped frame types, off-by-one in `wifictl_get_ap_record`, invalid `esp_event_handler_unregister(ESP_EVENT_ANY_BASE, ...)` call, NULL-deref path on non-EAPOL frames.
- Repo pushed to `github.com/kiruthick01/brute32`. Ran a full security/privacy sweep before first push — no leaked credentials/paths/keys found, `.gitignore` hardened (build/, sdkconfig, captures, managed_components, etc).
- README fixed twice: distorted ASCII logo (Unicode block chars don't render consistently — swapped for a figlet-generated plain-ASCII banner), added badges/TOC/collapsible sections, corrected the console command table to match actual `main.c` (was describing bssid-based commands, real ones are index-based) and the flash-size claim.
- Added `LICENSE` (MIT + Acceptable Use section).

**Hardware bring-up**
- Board: real ESP32-S3-N16R8 (16MB flash / 8MB embedded octal PSRAM). Verified legit — USB VID `0x303A` (Espressif's registered vendor ID), MAC OUI `7c:4f:ad` (Espressif-registered), `esptool flash_id` confirms 16MB flash matches the silkscreen.
- Native USB port didn't auto-reset into bootloader; had to use the board's separate UART-bridge port for `esptool`/`idf.py flash`.
- `sdkconfig.defaults` was wrong for this board (assumed 4MB flash, no PSRAM) — corrected to 16MB flash + octal PSRAM after confirming via `flash_id`.
- Caught and fixed a real bug from the boot log: no `nvs_flash_init()` call anywhere in `main.c`, so PHY calibration data could never be cached — every boot was doing a full RF calibration. Added proper init-with-erase-on-failure pattern.

**What's actually validated on real hardware now** (as opposed to just build-clean):
- `scan` — confirmed, real AP list with correct BSSID/channel/RSSI/SSID.
- `deauth` (broadcast) — confirmed the frame actually transmits (`wsl_bypasser`'s `ieee80211_raw_frame_sanity_check` override works against the real `libnet80211.a` blob on this chip/IDF combo, not just in theory).
- `deauth` forcing a real reconnect — confirmed, used it to kick a real connected client off "Redmi 13C 5G" test hotspot.
- `handshake` capture — confirmed complete end to end: `handshake <idx>` + `deauth <idx>` together produced a full captured 4-way handshake (pcap buffer went from empty header to 2269 bytes, `hccapx_serializer` reported a complete message pair).
- `save` + `fs_list` — confirmed, `redmi_test.pcap` (2269 bytes) and `redmi_test.hccapx` (393 bytes, matches `sizeof(hccapx_t)` exactly) both written to and listed from the SPIFFS `/captures` partition.
- `pmkid` — mechanically works (clean auth→assoc→run→init cycle, reproducible) but never actually captured a PMKID against the one target tried (Redmi hotspot likely doesn't advertise PMKID caching in M1). Target limitation, not a code bug — still unproven against a target that actually supports it.

**Known gaps / not yet touched**
- `deauth` targeted mode (specific `sta_mac` arg) — never exercised, only broadcast path.
- Found a real state-management gap during testing: forgot to call `pmkid_stop` after a failed PMKID attempt, which left `frame_analyzer`'s event handler still registered — next `handshake` start logged `event: handler already registered, overwriting`. Harmless in this case but the attack components don't currently guard against double-start; worth hardening later.
- Phase 2+ (evil twin, BLE, GPS/SD, display) — not started, per plan.

Next up: either get `pmkid` a real win against a PMKID-capable target, or move into Phase 2.
