/**
 * @file storage.c
 * @brief Implements the SPIFFS-backed storage abstraction.
 */
#include "storage.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_spiffs.h"

static const char *TAG = "storage";
#define MOUNT_POINT "/captures"

static bool mounted = false;

int storage_init() {
    if (mounted) {
        return ESP_OK;
    }

    esp_vfs_spiffs_conf_t conf = {
        .base_path = MOUNT_POINT,
        .partition_label = "storage",
        .max_files = 8,
        .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find SPIFFS partition 'storage'");
        } else {
            ESP_LOGE(TAG, "Failed to mount/format SPIFFS (%s)", esp_err_to_name(ret));
        }
        return ret;
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info("storage", &total, &used);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "SPIFFS mounted at %s: %d/%d bytes used", MOUNT_POINT, (int) used, (int) total);
    }

    mounted = true;
    return ESP_OK;
}

int storage_save_file(const char *name, const uint8_t *buffer, size_t size) {
    if (!mounted) {
        ESP_LOGE(TAG, "Storage not initialised");
        return ESP_ERR_INVALID_STATE;
    }

    char path[64];
    int written = snprintf(path, sizeof(path), "%s/%s", MOUNT_POINT, name);
    if (written < 0 || written >= (int) sizeof(path)) {
        ESP_LOGE(TAG, "File name too long: %s", name);
        return ESP_ERR_INVALID_ARG;
    }

    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open %s for writing", path);
        return ESP_FAIL;
    }

    size_t written_bytes = fwrite(buffer, 1, size, f);
    fclose(f);

    if (written_bytes != size) {
        ESP_LOGE(TAG, "Short write to %s: %d/%d bytes", path, (int) written_bytes, (int) size);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Saved %s (%d bytes)", path, (int) size);
    return ESP_OK;
}

int storage_list_files() {
    if (!mounted) {
        ESP_LOGE(TAG, "Storage not initialised");
        return -1;
    }

    DIR *dir = opendir(MOUNT_POINT);
    if (dir == NULL) {
        ESP_LOGE(TAG, "Failed to open %s", MOUNT_POINT);
        return -1;
    }

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char path[sizeof(MOUNT_POINT) + sizeof(entry->d_name) + 1];
        snprintf(path, sizeof(path), "%s/%s", MOUNT_POINT, entry->d_name);
        struct stat st;
        if (stat(path, &st) == 0) {
            ESP_LOGI(TAG, "%s (%ld bytes)", entry->d_name, (long) st.st_size);
        } else {
            ESP_LOGI(TAG, "%s", entry->d_name);
        }
        count++;
    }
    closedir(dir);
    return count;
}

int storage_get_usage(size_t *out_total, size_t *out_used) {
    if (!mounted) {
        return ESP_ERR_INVALID_STATE;
    }
    return esp_spiffs_info("storage", out_total, out_used);
}
