/**
 * @file storage.h
 * @brief Minimal SPIFFS abstraction for saving capture output (PCAP/HCCAPX) to flash.
 *
 * Backed by the "storage" partition declared in partitions.csv. This is a thin
 * wrapper so callers don't need to know the mount point or VFS details; a
 * microSD-backed implementation can be swapped in later (Phase 4) behind the
 * same interface.
 */
#ifndef STORAGE_H
#define STORAGE_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Mounts the SPIFFS "storage" partition. Safe to call multiple times.
 *
 * @return ESP_OK on success
 */
int storage_init();

/**
 * @brief Writes buffer to /captures/<name> (path length must be under 32 bytes,
 * a SPIFFS constraint), overwriting any existing file of the same name.
 *
 * @return ESP_OK on success
 */
int storage_save_file(const char *name, const uint8_t *buffer, size_t size);

/**
 * @brief Lists files currently in /captures, logging each name and size.
 *
 * @return number of files found, or -1 on error
 */
int storage_list_files();

/**
 * @brief Returns total and used bytes on the storage partition.
 */
int storage_get_usage(size_t *out_total, size_t *out_used);

#endif
