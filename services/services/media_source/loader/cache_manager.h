/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef CACHE_MANAGER_H
#define CACHE_MANAGER_H

#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <atomic>
#include <memory>
#include <securec.h>

namespace OHOS {
namespace Media {
// 字段ID定义
enum class CacheFieldId : uint32_t {
    KEY = 1,
    ENTRY = 2,
    TYPE = 3,
    RANDOM_ACCESS = 4,
    SIZE = 5,
    LAST_ACCESS_TIME = 6,
    REQUEST_URL = 7,
};

// 结构体定义
struct CacheEntryHeader {
    uint32_t version;
    uint32_t fieldCount;
};

struct CacheField {
    uint32_t id;
    uint32_t len;
};

struct CacheEntryInfo {
    size_t offset;
    size_t cacheEntrySize;
    CacheEntryInfo() = default;
    CacheEntryInfo(size_t offset, size_t cacheEntrySize)
        : offset(offset), cacheEntrySize(cacheEntrySize) {}
};

struct FileInfo {
    std::filesystem::path path;
    std::filesystem::file_time_type writeTime;
    uint64_t size;

    // 按修改时间升序排序
    bool operator<(const FileInfo& other) const
    {
        return writeTime < other.writeTime;
    }
};

class StreamCacheManager {
public:
    static std::shared_ptr<StreamCacheManager> Create();
    StreamCacheManager();
    ~StreamCacheManager();

    std::string GetMediaCache(const std::string& url);  // 根据url获取缓存目录更新访问时间
    bool CreateMediaCache(const std::string& url, const std::string& type,
        bool randomAccess, uint64_t size); // 添加缓存映射目录
    bool FlushWriteLength(const std::string& path, uint64_t fileSize);      //刷新缓存文件大小
    void ReleaseMap();

private:
    void LoadIndex();
    std::string ExtractField(char* entryStart, uint32_t fieldCount, CacheFieldId targetId);
    bool CreateDirectories(const std::string& path);
    uint64_t ScanDirectorySize(const std::string& path);
    bool FindFirstEqualField(const std::vector<CacheEntryInfo>& entries, CacheEntryInfo& result,
        const std::string& value, CacheFieldId field);
    void LoadMapping();
    bool UpdateLastAccessTime(CacheEntryInfo& info, const std::string& entry);
    std::string GetPrefixBeforeUnderscore(const std::string& str);
    bool RemoveCacheDirectory(const std::string& path);
    void FlushCacheSize(uint64_t size);
    bool RemoveMediaCache(const std::string& url);
    bool InsertMapping(const std::vector<std::pair<CacheFieldId, std::string>>& activeFields,
        size_t headerSize, size_t fieldsHeaderSize);

    static std::shared_ptr<StreamCacheManager> cacheManager_;
    static std::once_flag onceFlag_;
    int fd_;
    void* mapped_;
    size_t fileSize_;
    std::unordered_map<std::string, std::string> entryIndex_;
    std::unordered_map<std::string, std::vector<CacheEntryInfo>> index_;
    std::mutex mutex_;
    std::atomic<uint64_t> cacheSize_;
};
} // namespace Media
} // namespace OHOS
#endif