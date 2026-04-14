/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cache_mapping_format.h"
#include "path_validator.h"
#include "common/log.h"
#include "media_log.h"
#include <fstream>
#include <cstring>
#include <zlib.h>

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "DownloadedCacheMappingSerializer"};
}

namespace OHOS {
namespace Media {
namespace DownloadedCache {

uint32_t CacheMappingSerializer::CalculateHeaderChecksum(const CacheMappingHeader& header)
{
    const uint8_t* data = reinterpret_cast<const uint8_t*>(&header);
    size_t dataSize = sizeof(CacheMappingHeader) - sizeof(header.headerChecksum);

    // zlib CRC32函数：
    // 参数1: 初始CRC值（首次计算时为0）
    // 参数2: 数据缓冲区
    // 参数3: 数据长度
    // 返回: CRC32值
    uint32_t crc = crc32(0, data, static_cast<uInt>(dataSize));

    return crc;
}

bool CacheMappingSerializer::WriteHeader(std::ofstream& file, const CacheMappingHeader& header)
{
    if (!file.is_open()) {
        MEDIA_LOGE("File stream is not open");
        return false;
    }

    file.write(reinterpret_cast<const char*>(header.magic), sizeof(header.magic));
    file.write(reinterpret_cast<const char*>(&header.version), sizeof(header.version));
    file.write(reinterpret_cast<const char*>(&header.entryCount), sizeof(header.entryCount));
    file.write(reinterpret_cast<const char*>(header.reserved), sizeof(header.reserved));

    uint32_t checksum = CalculateHeaderChecksum(header);
    file.write(reinterpret_cast<const char*>(&checksum), sizeof(checksum));

    if (!file) {
        MEDIA_LOGE("Failed to write header to file");
        return false;
    }

    return true;
}

bool CacheMappingSerializer::WriteEntry(std::ofstream& file, const CacheMappingEntry& entry,
    const std::string& cacheDir)
{
    if (!file.is_open()) {
        MEDIA_LOGE("File stream is not open");
        return false;
    }

    if (!PathValidator::Validate(cacheDir, entry.filePath)) {
        MEDIA_LOGE("Invalid relative path: %{public}s", entry.filePath.c_str());
        return false;
    }

    file.write(reinterpret_cast<const char*>(entry.header.urlHash),
             sizeof(entry.header.urlHash));
    file.write(reinterpret_cast<const char*>(&entry.header.pathLength),
             sizeof(entry.header.pathLength));
    file.write(reinterpret_cast<const char*>(&entry.header.fileSize),
             sizeof(entry.header.fileSize));
    file.write(reinterpret_cast<const char*>(entry.header.reserved),
             sizeof(entry.header.reserved));

    file.write(entry.filePath.c_str(), entry.filePath.size());

    if (!file) {
        MEDIA_LOGE("Failed to write entry to file");
        return false;
    }

    return true;
}

bool CacheMappingDeserializer::ReadHeader(std::ifstream& file, CacheMappingHeader& header)
{
    if (!file.is_open()) {
        MEDIA_LOGE("File stream is not open");
        return false;
    }

    file.read(reinterpret_cast<char*>(header.magic), sizeof(header.magic));
    file.read(reinterpret_cast<char*>(&header.version), sizeof(header.version));
    file.read(reinterpret_cast<char*>(&header.entryCount), sizeof(header.entryCount));
    file.read(reinterpret_cast<char*>(header.reserved), sizeof(header.reserved));
    file.read(reinterpret_cast<char*>(&header.headerChecksum), sizeof(header.headerChecksum));

    if (!file) {
        MEDIA_LOGE("Failed to read header from file");
        return false;
    }

    return true;
}

bool CacheMappingDeserializer::ReadEntry(std::ifstream& file, CacheMappingEntry& entry,
    const std::string& cacheDir)
{
    if (!file.is_open()) {
        MEDIA_LOGE("File stream is not open");
        return false;
    }

    file.read(reinterpret_cast<char*>(entry.header.urlHash),
            sizeof(entry.header.urlHash));
    file.read(reinterpret_cast<char*>(&entry.header.pathLength),
            sizeof(entry.header.pathLength));
    file.read(reinterpret_cast<char*>(&entry.header.fileSize),
            sizeof(entry.header.fileSize));
    file.read(reinterpret_cast<char*>(entry.header.reserved),
            sizeof(entry.header.reserved));

    if (!file) {
        MEDIA_LOGE("Failed to read entry header from file");
        return false;
    }

    entry.filePath.resize(entry.header.pathLength);
    file.read(&entry.filePath[0], entry.header.pathLength);

    if (!file) {
        MEDIA_LOGE("Failed to read entry path from file");
        return false;
    }

    if (!PathValidator::Validate(cacheDir, entry.filePath)) {
        MEDIA_LOGW("Skipping entry with invalid path: %{public}s",
                  entry.filePath.c_str());
        return false;
    }

    return true;
}

bool CacheMappingDeserializer::ValidateHeader(const CacheMappingHeader& header)
{
    if (std::memcmp(header.magic, CACHE_MAPPING_MAGIC, 4) != 0) {
        MEDIA_LOGE("Invalid magic number: %{public}c%c%c%c",
                   header.magic[0], header.magic[1], header.magic[2], header.magic[3]);
        return false;
    }

    if (header.version != CACHE_MAPPING_VERSION) {
        MEDIA_LOGE("Unsupported version: %{public}u", header.version);
        return false;
    }

    uint32_t calculatedChecksum = CacheMappingSerializer::CalculateHeaderChecksum(header);
    if (header.headerChecksum != calculatedChecksum) {
        MEDIA_LOGE("Header checksum mismatch");
        return false;
    }

    return true;
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS