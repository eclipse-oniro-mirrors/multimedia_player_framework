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

#ifndef DOWNLOADED_CACHE_MAPPING_FORMAT_H
#define DOWNLOADED_CACHE_MAPPING_FORMAT_H

#include <cstdint>
#include <array>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <system_error>

namespace fs = std::filesystem;

namespace OHOS {
namespace Media {
namespace DownloadedCache {

constexpr uint8_t CACHE_MAPPING_MAGIC[4] = {'D', 'C', 'M', 'H'};  // ASCII: D=0x44, C=0x43, M=0x4D, H=0x48
constexpr uint32_t CACHE_MAPPING_VERSION = 1;

#pragma pack(push, 1)
struct CacheMappingHeader {
    uint8_t  magic[4];        // 魔数：'DCMH' (字符数组，避免字节序问题)
    uint32_t version;         // 版本号：1
    uint32_t entryCount;      // 条目数量
    uint8_t  reserved[8];     // 保留字段：8字节（放在条目数量之后、校验和之前）
    uint32_t headerChecksum;  // 头部校验和（CRC32，包含保留字段）
};
#pragma pack(pop)

static_assert(sizeof(CacheMappingHeader) == 24, "CacheMappingHeader size must be 24 bytes");

#pragma pack(push, 1)
struct CacheMappingEntryHeader {
    uint8_t  urlHash[32];     // URL的SHA256完整哈希值（32字节）
    uint32_t pathLength;       // 文件路径长度（UTF-8编码）
    uint64_t fileSize;         // 文件总大小（字节）
    uint8_t  reserved[8];      // 保留字段：8字节（在fileSize之后）
};
#pragma pack(pop)

static_assert(sizeof(CacheMappingEntryHeader) == 52, "CacheMappingEntryHeader size must be 52 bytes");

struct CacheMappingEntry {
    CacheMappingEntryHeader header;  // 52字节
    std::string filePath;            // 文件路径（UTF-8编码，相对路径）

    size_t GetTotalSize() const {
        return sizeof(header) + filePath.size();
    }
};

class CacheMappingSerializer {
public:
    static bool WriteHeader(std::ofstream& file, const CacheMappingHeader& header);
    static bool WriteEntry(std::ofstream& file, const CacheMappingEntry& entry, const std::string& cacheDir);
    static uint32_t CalculateHeaderChecksum(const CacheMappingHeader& header);
};

class CacheMappingDeserializer {
public:
    static bool ReadHeader(std::ifstream& file, CacheMappingHeader& header);
    static bool ReadEntry(std::ifstream& file, CacheMappingEntry& entry, const std::string& cacheDir);
    static bool ValidateHeader(const CacheMappingHeader& header);
};

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS

#endif // DOWNLOADED_CACHE_MAPPING_FORMAT_H