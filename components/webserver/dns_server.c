/**
 * @file dns_server.c
 * @brief Implements the captive-portal DNS hijack.
 *
 * Every incoming query gets a single-answer response pointing at our AP's
 * own IP (192.168.4.1, ESP-IDF's default AP netif address), regardless of
 * what was asked. Good enough to trigger OS captive-portal detection and
 * redirect ordinary browsing to our HTTP server.
 */
#include "dns_server.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "dns_server";

#define DNS_PORT 53
#define DNS_MAX_PACKET 512
// ESP-IDF's default AP netif address (see esp_netif_create_default_wifi_ap())
static const uint8_t AP_IP[4] = {192, 168, 4, 1};

static TaskHandle_t dns_task_handle = NULL;
static int dns_socket = -1;

typedef struct __attribute__((__packed__)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

/**
 * @brief Builds a single-answer reply in `out` for the query in `req`,
 * reusing the question section verbatim and pointing the answer at AP_IP.
 *
 * @return length of the reply, or 0 if the query is malformed
 */
static int build_reply(const uint8_t *req, int req_len, uint8_t *out, int out_cap) {
    if (req_len < (int) sizeof(dns_header_t)) {
        return 0;
    }

    const dns_header_t *req_hdr = (const dns_header_t *) req;
    if (ntohs(req_hdr->qdcount) < 1) {
        return 0;
    }

    // Walk the QNAME to find where the question section ends (name + qtype(2) + qclass(2))
    int pos = sizeof(dns_header_t);
    while (pos < req_len && req[pos] != 0x00) {
        uint8_t label_len = req[pos];
        if (label_len & 0xC0) {
            // Compression pointer in a query is unusual; bail rather than mis-parse
            return 0;
        }
        pos += 1 + label_len;
        if (pos >= req_len) {
            return 0;
        }
    }
    pos += 1; // terminating zero label
    int question_end = pos + 4; // + QTYPE + QCLASS
    if (question_end > req_len || question_end > out_cap) {
        return 0;
    }

    memcpy(out, req, question_end);
    dns_header_t *resp_hdr = (dns_header_t *) out;
    resp_hdr->flags = htons(0x8180); // standard query response, no error, recursion available
    resp_hdr->qdcount = htons(1);
    resp_hdr->ancount = htons(1);
    resp_hdr->nscount = 0;
    resp_hdr->arcount = 0;

    int reply_len = question_end;
    if (reply_len + 16 > out_cap) {
        return 0;
    }

    out[reply_len++] = 0xC0; // name: pointer to question's QNAME at offset 0x0C
    out[reply_len++] = 0x0C;
    out[reply_len++] = 0x00; // TYPE = A
    out[reply_len++] = 0x01;
    out[reply_len++] = 0x00; // CLASS = IN
    out[reply_len++] = 0x01;
    out[reply_len++] = 0x00; // TTL = 60s
    out[reply_len++] = 0x00;
    out[reply_len++] = 0x00;
    out[reply_len++] = 0x3C;
    out[reply_len++] = 0x00; // RDLENGTH = 4
    out[reply_len++] = 0x04;
    memcpy(&out[reply_len], AP_IP, 4);
    reply_len += 4;

    return reply_len;
}

static void dns_server_task(void *pvParameters) {
    uint8_t req[DNS_MAX_PACKET];
    uint8_t resp[DNS_MAX_PACKET];

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int len = recvfrom(dns_socket, req, sizeof(req), 0, (struct sockaddr *) &client_addr, &addr_len);
        if (len <= 0) {
            if (dns_socket < 0) {
                break; // socket was closed by dns_server_stop()
            }
            continue;
        }

        int reply_len = build_reply(req, len, resp, sizeof(resp));
        if (reply_len > 0) {
            sendto(dns_socket, resp, reply_len, 0, (struct sockaddr *) &client_addr, addr_len);
        }
    }

    dns_task_handle = NULL;
    vTaskDelete(NULL);
}

void dns_server_start() {
    if (dns_task_handle != NULL) {
        return;
    }

    dns_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dns_socket < 0) {
        ESP_LOGE(TAG, "Failed to create DNS socket");
        return;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(dns_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
        ESP_LOGE(TAG, "Failed to bind DNS socket to port %d", DNS_PORT);
        close(dns_socket);
        dns_socket = -1;
        return;
    }

    xTaskCreate(&dns_server_task, "dns_server", 4096, NULL, 5, &dns_task_handle);
    ESP_LOGI(TAG, "DNS hijack started, answering everything as %d.%d.%d.%d", AP_IP[0], AP_IP[1], AP_IP[2], AP_IP[3]);
}

void dns_server_stop() {
    if (dns_socket >= 0) {
        int s = dns_socket;
        dns_socket = -1;
        shutdown(s, SHUT_RDWR);
        close(s);
    }
}
