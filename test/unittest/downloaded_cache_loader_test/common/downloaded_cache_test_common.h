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

#ifndef DOWNLOADED_CACHE_TEST_COMMON_H
#define DOWNLOADED_CACHE_TEST_COMMON_H

#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <unistd.h>

#include "cache_mapping_format.h"
#include "sha256_hasher.h"

namespace fs = std::filesystem;

namespace OHOS {
namespace Media {
namespace DownloadedCache {
namespace TestCommon {

constexpr const char* TEST_BASE_DIR = "/data/test/downloaded_cache_loader_test";
constexpr const char* TEST_MAPPING_FILE = "cache_mapping.txt";

inline std::string GetTestCacheDir(const std::string& subdir)
{
    return std::string(TEST_BASE_DIR) + "_" + subdir + "_" + std::to_string(getpid());
}

inline void CreateTestCacheFile(const std::string& cacheDir, const std::string& relativePath,
    const std::vector<uint8_t>& data)
{
    std::string fullPath = cacheDir + "/" + relativePath;
    fs::create_directories(fs::path(fullPath).parent_path());

    std::ofstream file(fullPath, std::ios::binary | std::ios::trunc);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        file.close();
    }
}

inline void CreateTestMappingFile(const std::string& cacheDir,
    const std::vector<std::pair<std::string, std::string>>& entries,
    uint64_t fileSize = 1024)
{
    std::string mappingPath = cacheDir + "/" + TEST_MAPPING_FILE;

    CacheMappingHeader header;
    memcpy(header.magic, CACHE_MAPPING_MAGIC, 4);
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = static_cast<uint32_t>(entries.size());
    memset(header.reserved, 0, 8);
    header.headerChecksum = CacheMappingSerializer::CalculateHeaderChecksum(header);

    std::ofstream file(mappingPath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        return;
    }

    file.write(reinterpret_cast<const char*>(header.magic), 4);
    file.write(reinterpret_cast<const char*>(&header.version), 4);
    file.write(reinterpret_cast<const char*>(&header.entryCount), 4);
    file.write(reinterpret_cast<const char*>(header.reserved), 8);
    file.write(reinterpret_cast<const char*>(&header.headerChecksum), 4);

    for (const auto& entry : entries) {
        auto hash = SHA256Hasher::GenerateHash(entry.first);
        uint32_t pathLength = static_cast<uint32_t>(entry.second.size());
        uint64_t size = fileSize;
        uint8_t reserved[8] = {0};

        file.write(reinterpret_cast<const char*>(hash.data()), SHA256_LEN);
        file.write(reinterpret_cast<const char*>(&pathLength), 4);
        file.write(reinterpret_cast<const char*>(&size), 8);
        file.write(reinterpret_cast<const char*>(reserved), 8);
        file.write(entry.second.c_str(), entry.second.size());
    }

    file.close();
}

inline void CreateTestMappingFileWithChecksum(const std::string& cacheDir,
    const std::vector<std::pair<std::string, std::string>>& entries,
    uint32_t checksumOverride)
{
    std::string mappingPath = cacheDir + "/" + TEST_MAPPING_FILE;

    CacheMappingHeader header;
    memcpy(header.magic, CACHE_MAPPING_MAGIC, 4);
    header.version = CACHE_MAPPING_VERSION;
    header.entryCount = static_cast<uint32_t>(entries.size());
    memset(header.reserved, 0, 8);
    header.headerChecksum = checksumOverride;

    std::ofstream file(mappingPath, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        return;
    }

    file.write(reinterpret_cast<const char*>(header.magic), 4);
    file.write(reinterpret_cast<const char*>(&header.version), 4);
    file.write(reinterpret_cast<const char*>(&header.entryCount), 4);
    file.write(reinterpret_cast<const char*>(header.reserved), 8);
    file.write(reinterpret_cast<const char*>(&header.headerChecksum), 4);
    file.close();
}

inline void CleanupTestDirectory(const std::string& cacheDir)
{
    if (fs::exists(cacheDir)) {
        fs::remove_all(cacheDir);
    }
}

inline void SetupTestDirectory(const std::string& cacheDir)
{
    CleanupTestDirectory(cacheDir);
    fs::create_directories(cacheDir);
}

inline void CreateRawMappingFile(const std::string& cacheDir, const std::vector<uint8_t>& data)
{
    std::string mappingPath = cacheDir + "/" + TEST_MAPPING_FILE;
    std::ofstream file(mappingPath, std::ios::binary | std::ios::trunc);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        file.close();
    }
}

} // namespace TestCommon
} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS

#endif // DOWNLOADED_CACHE_TEST_COMMON_H