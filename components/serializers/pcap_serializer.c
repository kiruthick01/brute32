/**
 * @file pcap_serializer.c
 * @brief Implementation of PCAP serializer.
 */
#include "pcap_serializer.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"

static const char *TAG = "pcap_serializer";

/**
 * @see Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#global-header
 */
#define SNAPLEN 65535
#define PCAP_MAGIC_NUMBER 0xa1b2c3d4

/**
 * @see Ref: http://www.tcpdump.org/linktypes.html (LINKTYPE_IEEE802_11)
 */
#define LINKTYPE_IEEE802_11 105

static unsigned pcap_size = 0;
static uint8_t *pcap_buffer = NULL;

uint8_t *pcap_serializer_init() {
    free(pcap_buffer);
    pcap_global_header_t pcap_global_header = {
        .magic_number = PCAP_MAGIC_NUMBER,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = SNAPLEN,
        .network = LINKTYPE_IEEE802_11
    };
    pcap_buffer = (uint8_t *) malloc(sizeof(pcap_global_header_t));
    if (pcap_buffer == NULL) {
        ESP_LOGE(TAG, "Failed to allocate PCAP global header");
        pcap_size = 0;
        return NULL;
    }
    pcap_size = sizeof(pcap_global_header_t);
    memcpy(pcap_buffer, &pcap_global_header, sizeof(pcap_global_header_t));
    return pcap_buffer;
}

void pcap_serializer_append_frame(const uint8_t *buffer, unsigned size, unsigned ts_usec) {
    if (size == 0) {
        ESP_LOGD(TAG, "Frame size is 0. Not appending anything.");
        return;
    }
    if (size > SNAPLEN) {
        size = SNAPLEN;
    }
    pcap_record_header_t pcap_record_header = {
        .ts_sec = ts_usec / 1000000,
        .ts_usec = ts_usec % 1000000,
        .incl_len = size,
        .orig_len = size,
    };

    uint8_t *reallocated_pcap_buffer = realloc(pcap_buffer, pcap_size + sizeof(pcap_record_header_t) + size);
    if (reallocated_pcap_buffer == NULL) {
        ESP_LOGE(TAG, "Error reallocating PCAP buffer! PCAP buffer may not be complete.");
        return;
    }
    memcpy(&reallocated_pcap_buffer[pcap_size], &pcap_record_header, sizeof(pcap_record_header_t));
    memcpy(&reallocated_pcap_buffer[pcap_size + sizeof(pcap_record_header_t)], buffer, size);
    pcap_buffer = reallocated_pcap_buffer;
    pcap_size += sizeof(pcap_record_header_t) + size;
}

void pcap_serializer_deinit() {
    free(pcap_buffer);
    pcap_buffer = NULL;
    pcap_size = 0;
}

unsigned pcap_serializer_get_size() {
    return pcap_size;
}

uint8_t *pcap_serializer_get_buffer() {
    return pcap_buffer;
}
