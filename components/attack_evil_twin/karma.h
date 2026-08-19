/**
 * @file karma.h
 * @brief Internal karma-style probe-request responder for attack_evil_twin.
 *
 * Not part of the component's public interface — see attack_evil_twin.h.
 */
#ifndef KARMA_H
#define KARMA_H

#include <stdint.h>
#include "attack_evil_twin.h"

/**
 * @brief Starts sniffing probe requests on the given channel and replying
 * to each with a spoofed probe response advertising the requested SSID
 * from our_bssid.
 *
 * @param channel channel our rogue AP is currently operating on
 * @param our_bssid 6-byte MAC to source probe responses from (our AP's BSSID)
 */
void karma_start(uint8_t channel, const uint8_t *our_bssid);

/**
 * @brief Stops the karma responder.
 */
void karma_stop();

/**
 * @brief Copies up to max_count logged probe requests into out, newest first.
 *
 * @return number of entries written
 */
unsigned karma_get_log(karma_probe_t *out, unsigned max_count);

#endif
