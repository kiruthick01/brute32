# Dev Log

Rough running notes, not polished docs. Newest entry on top.

---

## 2026-08-20 (4)

Fixed the leading spam-address-format hypothesis from the previous entry, retested on hardware — still no popup. Narrows the remaining suspects down to payload byte fidelity / OS hardening.

**What changed**
- `blespam` was advertising from a Non-Resolvable Private Address (`ble_hs_id_gen_rnd(1, ...)`, top address bits `00`). Real Apple/Google devices always advertise Continuity/Fast Pair data from a Resolvable Private Address (top bits `01`) — plausible that iOS/Android filter out spam-shaped payloads before parsing them if the sender address doesn't even look like a real device's rotating identity.
- Switched to controller-based RPA: `ble_controller.c`'s `on_sync` now generates and sets a static random identity address (`ble_hs_id_gen_rnd(0, ...)` + `ble_hs_id_set_rnd`) once, and sets the RPA rotation period to the HCI minimum (`ble_hs_set_rpa_timeout(1)`, 1 second). `spam_tick` now advertises with `own_addr_type=BLE_OWN_ADDR_RPA_RANDOM_DEFAULT` instead of manually re-randomizing an NRPA every tick — the ESP32-S3 controller now generates and rotates a real RPA itself, using the identity IRK the NimBLE host auto-provisions during startup (`ble_hs_startup.c`, no app-level IRK call needed — tried calling `ble_hs_pvcy_set_our_irk()` directly first, turned out to be a private/internal symbol not in the public header, not usable from application code).

**Hardware retest**
- `blespam apple 300` and `blespam android 300`, 20s each, run clean — `ble_gap_adv_start` never returned an error on any tick, confirming the RPA-based advertising configuration is accepted by the controller (the old NRPA path also never errored, so this isn't itself proof the address format was wrong, just that the fix didn't break anything).
- **Still no popup on the same real iPhone (apple mode) or real Android phone (android mode).**

**Where this leaves it**
- Address format was a reasonable, checkable hypothesis and is now fixed regardless of outcome (real RPA is objectively more correct than NRPA for this use case). But it wasn't the (sole) blocker.
- Remaining suspects, unchanged from before: the specific Continuity action-type bytes and Fast Pair model IDs in `apple_action_types[]` / `fastpair_model_ids[]` are still just plausible-shaped guesses reconstructed from public write-ups, not confirmed-correct values — most likely explanation at this point. OS-version hardening (both test phones are current-gen) remains a live possibility too.
- Next real step if this gets picked back up: stop guessing values and cross-reference against a source of ground truth — e.g. use `blescan`'s existing manufacturer-data capture to log real Apple/Google device advertisements nearby and diff their byte structure against what we're sending, rather than iterating on more guessed byte tables blind.

---

## 2026-08-20 (3)

Phase 3 hardware-tested: `blescan`/`bledevices` confirmed working, `blespam` mechanically confirmed but payload fidelity gap is real, not just theoretical.

- **`blescan 10` + `bledevices`** — confirmed against real hardware: 25 real nearby BLE devices captured in one scan, RSSI/connectable-flag/manufacturer-company-ID/advertised-name all populated correctly (real device names came through: "OnePlus Nord Buds 3r", "KAMESHWAR", "realme Buds T200 Lite(BLE)", "Galaxy Buds2 Pro LE"; company ID `0x004c` = Apple showed up repeatedly as expected from nearby iPhones/AirPods).
- **Found and fixed a real crash** during this same test: `bledevices` stack-overflowed the `console_repl` task and rebooted the board. Root cause: `cmd_bledevices` put a full `CONFIG_BLE_MAX_DEVICES`-entry `ble_device_t[]` on the console task's stack (~4KB default) as a local — fine for `blescan`'s internal static table, not fine as a stack local in a command handler. Fixed by making it `static` in `main.c`. Also fixed a cosmetic bug caught in the same pass: unknown company ID printed as `-0000` instead of `-`. Rebuilt clean, reflashed, reran — 25 devices listed, no crash.
- **`blespam apple 300`** and **`blespam android 300`** — both ran 20s straight against real nearby phones with no crash, no error, advertising restarted every 300ms with a fresh random address each cycle (confirmed via NimBLE logs: `GAP procedure initiated: stop advertising` / `advertise` pairs every tick). **No popup on either a nearby iPhone (apple mode) or a nearby Android phone (android mode).** This confirms the fidelity gap flagged in the previous entry is real: the AD-structure/company-ID/service-UUID framing works (packets are legitimately shaped Continuity/Fast Pair advertisements), but the specific action-type bytes (`apple_action_types[]`) and Fast Pair model IDs (`fastpair_model_ids[]`) in `ble_controller.c` don't trigger a popup on either OS as currently chosen — need real correct values, not just plausible-shaped ones.
- Both target phones were current-generation flagship devices (recent iOS, recent Android) — plausible that popup-triggering conditions are pickier now (proximity/RSSI threshold, iOS/Android version gating, or the specific byte values being simply wrong) than what older public write-ups describe. Not root-caused yet.

Next: find corrected/verified Continuity action-type and Fast Pair model-ID byte values (cross-check multiple sources, or capture real Apple/Android device advertisements with `blescan`'s manufacturer-data output for comparison) rather than guessing further blind.

---

## 2026-08-20 (2)

Phase 3 (BLE recon + advertising-layer spam) built, build-verified, not yet flash-tested.

**What got built**
- `components/ble_controller/` — NimBLE bring-up (`nimble_port_init` + host FreeRTOS task, no GATT server needed for scan/spam-only roles). Two pieces:
  - **Scan**: passive-central active GAP scan (`ble_gap_disc`), own dedup-by-address table (`CONFIG_BLE_MAX_DEVICES` entries, Kconfig-tunable) instead of the controller's `filter_duplicates` so RSSI/fields keep updating per device across the scan window. Parses name + manufacturer-data company ID out of `ble_hs_adv_fields` for basic fingerprinting.
  - **Spam**: peripheral-role non-connectable advertising, `esp_timer`-driven cycle that on every tick stops advertising, generates a new NRPA random address (`ble_hs_id_gen_rnd` + `ble_hs_id_set_rnd`) so each broadcast reads as a distinct device, builds a forged AD payload (Apple Continuity "Nearby Action" manufacturer data, or Google Fast Pair service data under UUID 0xFE2C), and restarts advertising — matches how public BLE-spam tools trigger repeated OS-level pairing popups.
  - Flagged explicitly, matching the plan's ask: spam is disruptive-by-design, isolated-test-environments-only, console command prints that warning every time it's started.
- Console commands: `blescan [sec]`, `blescan_stop`, `bledevices`, `blespam <apple|android|all> [ms]`, `blespam_stop`.
- `sdkconfig.defaults` gained NimBLE-only BT config (`CONFIG_BT_NIMBLE_ENABLED=y`, Bluedroid off, BLE-only controller mode) — mirrors the standard ESP-IDF NimBLE example defaults.

**Build verification**
- `idf.py build` clean on IDF 5.3.2 / `esp32s3`, zero warnings, 47% app-partition flash free. `bt` and `ble_controller` both correctly resolved into the component graph (confirmed via `idf.py set-target esp32s3` component listing).
- **Not yet hardware-tested** — no real device has scanned nearby BLE traffic through `blescan`, and no phone has been checked for an actual popup from `blespam`. Per this repo's own bar (see PMKID/eviltwin below), "builds clean" and "works" are different claims — Phase 3 is only the former so far.

**Known fidelity gap, flagged up front**
- The `blespam` Apple/Android payload byte values (action-type codes, Fast Pair model IDs) are reconstructed from public reverse-engineering write-ups, not from Apple/Google specs — the AD structure (manufacturer-data framing, company ID 0x004C, Fast Pair service UUID 0xFE2C) is solid, but which exact byte triggers which exact popup on which OS version is unverified. Needs a real round of hardware testing against real phones to confirm/correct.

Next up: flash-test `blescan` against known-nearby BLE peripherals (phone, headphones) to confirm the device table populates correctly, then `blespam` against a real iOS/Android device to see whether any payload variant actually produces a popup — adjust action-type/model-ID tables based on what's observed, same iterative approach PMKID and eviltwin took.

---

## 2026-08-20

Phase 2 (evil twin / rogue AP / captive portal) built and partially validated on hardware.

**What got built**
- `components/attack_evil_twin/` — clones a target AP's BSSID/SSID/channel with open auth so clients associate freely. Includes `karma.c`, a probe-request responder: sniffs probe requests and replies with a forged probe response advertising whatever SSID was requested, sourced from our rogue AP's BSSID. Reuses `attack_deauth`'s `wsl_bypasser` symbol-override trick for raw frame injection (no need to redefine it — it patches `esp_wifi_80211_tx` process-wide once linked in).
  - Documented real limitation up front: esp_wifi's AP mode only completes real associations for the one SSID it's actively configured with, so karma can make the rogue AP visually answer to any probed name but can't actually complete a connection under a name other than the currently cloned one. That's a driver/hardware ceiling, not a missing feature.
- `components/webserver/` — captive portal: `esp_http_server` wildcard catch-all handler serving a sign-in page, `dns_server.c` (minimal hand-rolled UDP DNS hijack answering every query with our own AP IP so client OSes trigger their captive-portal popup), and a POST handler that verifies the submitted password *live* against the real target AP via `wifictl_sta_connect_to_ap` before accepting it — wrong guesses re-serve the form with an error, matching how real phishing portals behave.
- Console commands: `eviltwin <index>`, `eviltwin_stop` (also restores the management AP), `karma_log`, `creds`.
- Full spec built in one pass (rogue AP + captive portal + karma), not the reduced core-only scope — deliberately took the harder option when asked.

**Hardware validation — partial**
- `eviltwin`/`eviltwin_stop` mechanically confirmed: starts clean (AP clone up, karma sniffer up, DNS hijack up, HTTP server up), stops clean (management AP correctly restored afterward, verified via `status` still responding post-stop).
- SSID clone confirmed real and visible to two independent devices: a second laptop saw both "mogger" and a macOS-deduplicated "mogger 2" side by side, and a MacBook explicitly flagged the clone with `"mogger" was previously joined as WPA2/WPA3 Personal, not Open. Are you sure you want to join this network?` — both are hard confirmation the rogue AP broadcasts correctly and is indistinguishable enough from the real network to trigger OS-level duplicate-SSID handling.
- **Not confirmed**: an actual completed join + portal page + captured password. Every join attempt (tried twice, once with karma disabled as a diagnostic to rule it out as the cause) resulted in zero AP-side log activity at all — no auth, no assoc, nothing — meaning the client never actually transmitted a real join frame our AP could see. Root cause traced to macOS's own security handling for previously-paired Personal Hotspot networks: it appears to silently refuse to transmit real 802.11 join frames to a security-mismatched network sharing a cached hotspot's SSID, even after clicking through the warning dialog. This is client-side OS behavior, not a firmware bug — ruled out by disabling karma entirely and reproducing the identical zero-activity result.
- Follow-up: retest against a device with no prior pairing history to the target SSID (a phone that's never connected to it, or a non-Apple OS) to get a real end-to-end confirmation of the captive portal + credential verification flow.

**Also**: caught and reverted a scope-creep detour mid-session — briefly added an `ssid_override` parameter to `attack_evil_twin_start` in response to a misread instruction, cleanly reverted before it shipped once the actual ask (target a specific real hotspot named "mogger", not rename the display SSID) was clarified.

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
