/**
 * @file dns_server.h
 * @brief Minimal captive-portal DNS hijack: answers every query with our
 * own AP IP so client OSes trigger their captive-portal browser popup.
 *
 * Internal to webserver; not part of its public interface.
 */
#ifndef DNS_SERVER_H
#define DNS_SERVER_H

/**
 * @brief Starts the DNS hijack task, bound to the AP netif's IP.
 */
void dns_server_start();

/**
 * @brief Stops the DNS hijack task.
 */
void dns_server_stop();

#endif
