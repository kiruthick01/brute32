/**
 * @file frame_analyzer_parser.h
 * @brief Interface for parsing 802.11 data frames into EAPoL / PMKID structures.
 */
#ifndef FRAME_ANALYZER_PARSER_H
#define FRAME_ANALYZER_PARSER_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_wifi_types.h"

#include "frame_analyzer_types.h"

/**
 * @brief Determines whether BSSID inside of the given frame matches given BSSID.
 */
bool is_frame_bssid_matching(wifi_promiscuous_pkt_t *frame, const uint8_t *bssid);

/**
 * @brief Parses EAPoL packet from given frame.
 *
 * @return eapol_packet_t* if parsing successful
 * @return NULL if no EAPoL packet was found, or the frame is protected
 */
eapol_packet_t *parse_eapol_packet(data_frame_t *frame);

/**
 * @brief Parses EAPoL-Key packet from EAPoL packet
 *
 * @note result does not include EAPoL header
 * @return eapol_key_packet_t* if parsing successful, NULL otherwise
 */
eapol_key_packet_t *parse_eapol_key_packet(eapol_packet_t *eapol_packet);

/**
 * @brief Parses PMKIDs from EAPoL-Key packet
 *
 * @return pmkid_item_t* linked list of PMKIDs if parsing successful
 * @return NULL if no key data present, key data are encrypted, or parsing fails
 */
pmkid_item_t *parse_pmkid(eapol_key_packet_t *eapol_key);

#endif
