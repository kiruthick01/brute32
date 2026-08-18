/**
 * @file sniffer.h
 * @brief Interface for promiscuous-mode sniffer functionality.
 */
#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_event.h"

ESP_EVENT_DECLARE_BASE(SNIFFER_EVENTS);

enum {
    SNIFFER_EVENT_CAPTURED_DATA,
    SNIFFER_EVENT_CAPTURED_MGMT,
    SNIFFER_EVENT_CAPTURED_CTRL
};

/**
 * @brief Sets sniffer filter for specific frame types.
 */
void wifictl_sniffer_filter_frame_types(bool data, bool mgmt, bool ctrl);

/**
 * @brief Start promiscuous mode on given channel
 */
void wifictl_sniffer_start(uint8_t channel);

/**
 * @brief Stop promiscuous mode
 */
void wifictl_sniffer_stop();

#endif
