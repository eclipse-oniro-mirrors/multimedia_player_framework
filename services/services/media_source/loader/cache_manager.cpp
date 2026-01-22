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

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <sys/stat.h>
#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include "cache_manager.h"
#include "media_log.h"
#include "scoped_timer.h"

namespace fs = std::filesystem;
using namespace std::chrono;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "StreamCacheManager"};
}

namespace OHOS {
namespace Media {
static const uint32_t FILED_COUNT = 7;
static const uint32_t MAX_FILED_COUNT = 7;
static const uint32_t VERSION = 1;
static const uint64_t MAX_CACHE_FILE_SIZE = 4ULL * 1024ULL * 1024ULL * 1024ULL;
static const uint64_t CACHE_FILE_SIZE_WATERLINE = 3ULL * 1024ULL * 1024ULL * 1024ULL;
static const uint64_t NEED_REMOVE_CACHE_SIZE = 800ULL * 1024ULL * 1024ULL;
static const std::string CACHE_DIR = "/data/storage/el2/base/cache/avplayer_media_loader";
static const std::string CACHE_MAPPING_FILE = "cache_mapping.txt";

std::once_flag StreamCacheManager::onceFlag_;
std::shared_ptr<StreamCacheManager> StreamCacheManager::cacheManager_;
std::shared_ptr<StreamCacheManager> StreamCacheManager::Create()
{
    std::call_once(onceFlag_, [] {
        cacheManager_ = std::make_shared<StreamCacheManager>();
        MEDIA_LOGI("createManager success");
    });
    return cacheManager_;
}

StreamCacheManager::StreamCacheManager():fd_(-1), mapped_(MAP_FAILED), file_size_(0)
{
    ScopedTimer timer("StreamCacheManager init", 10);
    LoadMapping();
    LoadIndex();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

void StreamCacheManager::LoadMapping()
{
    CreateDirectories(CACHE_DIR);
    cacheSize_.store(ScanDirectorySize(CACHE_DIR), std::memory_order_relaxed);
    std::string path = CACHE_DIR + fs::path::preferred_separator + CACHE_MAPPING_FILE;
    fd_ = open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    CHECK_AND_RETURN_LOG(fd_ != -1, "open mapping file failed");

    struct stat st;
    CHECK_AND_RETURN_LOG(fstat(fd_, &st) != -1, "fstat fd failed");

    file_size_ = st.st_size;
    if (file_size_ == 0) {
        MEDIA_LOGI("file_size is zero");
        return;
    }

    // 映射文件
    mapped_ = mmap(nullptr, file_size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
}

StreamCacheManager::~StreamCacheManager()
{
    if (mapped_ != MAP_FAILED) {
        munmap(mapped_, file_size_);
    }
    if (fd_ != -1) {
        close(fd_);
    }
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void StreamCacheManager::LoadIndex()
{
    CHECK_AND_RETURN_LOG(mapped_ != MAP_FAILED, "mapped is invalid");
    char* ptr = static_cast<char*>(mapped_);
    size_t offset = 0;
    while (offset < file_size_) {
        CHECK_AND_RETURN_LOG(offset + sizeof(CacheEntryHeader) < file_size_, "header size exceed file size");
        CacheEntryHeader* header = reinterpret_cast<CacheEntryHeader*>(ptr + offset);
        CHECK_AND_RETURN_LOG(header != nullptr, "reinterpret_cast CacheEntryHeader is null");
        if (header->fieldCount > MAX_FILED_COUNT) {
            // 文件损坏
            MEDIA_LOGE("file corruption cleans up directory");
            fs::remove_all(CACHE_DIR);
            index_.clear();
            entryIndex_.clear();
            LoadMapping();
            return;
        }
        size_t fieldsSize = header->fieldCount * sizeof(CacheField);
        CHECK_AND_RETURN_LOG(offset + sizeof(CacheEntryHeader) + fieldsSize < file_size_,
            "fieldSize exceeds file size, fieldCount:%{public}d", header->fieldCount);

        // 读取所有字段头
        CacheField* fields = reinterpret_cast<CacheField*>(ptr + offset + sizeof(CacheEntryHeader));
        size_t totalSize = sizeof(CacheEntryHeader) + fieldsSize;
        for (uint32_t i = 0; i < header->fieldCount; ++i) {
            totalSize += fields[i].len;
        }

        // 提取字段
        std::string key = ExtractField(ptr + offset, header->fieldCount, CacheFieldId::KEY);
        std::string entry = ExtractField(ptr + offset, header->fieldCount, CacheFieldId::ENTRY);
        std::string lastAccessTime = ExtractField(ptr + offset, header->fieldCount, CacheFieldId::LAST_ACCESS_TIME);
        entryIndex_[entry] = lastAccessTime;
        index_[key].emplace_back(offset, totalSize);

        offset += totalSize;
    }
}

bool StreamCacheManager::FlushWriteLength(const std::string& path, uint64_t fileSize)
{
    (void)path;
    cacheSize_.fetch_add(fileSize, std::memory_order_relaxed);
    CHECK_AND_RETURN_RET_NOLOG(cacheSize_.load() > MAX_CACHE_FILE_SIZE, true);

    MEDIA_LOGD("Clean cache directory start");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(mapped_ != MAP_FAILED, false, "mapped is invalid");
    std::vector<std::pair<std::string, std::string>> sortedVec;
    sortedVec.reserve(entryIndex_.size());

    for (const auto& kv : entryIndex_) {
        sortedVec.push_back(kv);
    }

    // 访问时间排序
    std::sort(sortedVec.begin(), sortedVec.end(),
        [](const auto& a, const auto& b) {
            return a.second < b.second;
        });
    for (const auto& cacheEntry : sortedVec) {
        CHECK_AND_RETURN_RET_NOLOG(cacheSize_.load() > CACHE_FILE_SIZE_WATERLINE, true);
        std::string entry = cacheEntry.first;
        std::string key = GetPrefixBeforeUnderscore(entry);
        uint64_t size = ScanDirectorySize(CACHE_DIR + fs::path::preferred_separator + entry);
        auto it = index_.find(key);
        if (size < NEED_REMOVE_CACHE_SIZE && it != index_.end()) {
            CacheEntryInfo info;
            FindFirstEqualField(it->second, info, entry, CacheFieldId::ENTRY);
            char* ptr = static_cast<char*>(mapped_);
            CacheEntryHeader* header = reinterpret_cast<CacheEntryHeader*>(ptr + info.offset);
            std::string url = ExtractField(ptr + info.offset, header->fieldCount, CacheFieldId::REQUEST_URL);
            RemoveMediaCache(url);
            FlushCacheSize(size);
        } else {
            RemoveCacheDirectory(CACHE_DIR + fs::path::preferred_separator + entry);
        }
    }
    MEDIA_LOGD("Clean cache directory end");

    return true;
}

std::string StreamCacheManager::ExtractField(char* entryStart, uint32_t fieldCount, CacheFieldId targetId)
{
    char* ptr = entryStart;
    ptr += sizeof(CacheEntryHeader);

    CacheField* fields = reinterpret_cast<CacheField*>(ptr);

    size_t offset = 0;
    for (uint32_t i = 0; i < fieldCount; ++i) {
        if (static_cast<uint32_t>(targetId) == fields[i].id) {
            return std::string(ptr + sizeof(CacheField) * fieldCount + offset, fields[i].len);
        }
        offset += fields[i].len;
    }
    return "";
}

bool StreamCacheManager::CreateMediaCache(const std::string& url, const std::string& type,
    bool randomAccess, uint64_t size)
{
    std::unique_lock<std::mutex> lock(mutex_);
    std::string key = std::to_string(std::hash<std::string>()(url));
    auto it = index_.find(key);
    CacheEntryInfo info;
    CHECK_AND_RETURN_RET_LOG(it == index_.end() ||
        !FindFirstEqualField(it->second, info, url, CacheFieldId::REQUEST_URL), true, "has create media cache");

    auto millisec_since_epoch = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    std::string lastAccessTime = std::to_string(millisec_since_epoch);
    std::string entry = it != index_.end() ? key + "_" + lastAccessTime : key;

    std::vector<std::pair<CacheFieldId, std::string>> activeFields = {
        { CacheFieldId::KEY, key },
        { CacheFieldId::ENTRY, entry },
        { CacheFieldId::TYPE, type },
        { CacheFieldId::RANDOM_ACCESS, std::to_string(randomAccess) },
        { CacheFieldId::SIZE, std::to_string(size) },
        { CacheFieldId::LAST_ACCESS_TIME, lastAccessTime },
        { CacheFieldId::REQUEST_URL, url },
    };

    size_t headerSize = sizeof(CacheEntryHeader);
    size_t fieldsHeaderSize = FILED_COUNT * sizeof(CacheField);
    size_t contentSize = 0;
    for (auto& f : activeFields) {
        contentSize += f.second.size();
    }

    size_t totalSize = headerSize + fieldsHeaderSize + contentSize;
    CHECK_AND_RETURN_RET_LOG(ftruncate(fd_, file_size_ + totalSize) != -1, false,
        "ftruncate failed:%{public}s", strerror(errno));

    // 重新映射
    void* newMapped = mmap(nullptr, file_size_ + totalSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    CHECK_AND_RETURN_RET_LOG(newMapped != MAP_FAILED, false, "mmap failed: %{public}s", strerror(errno));
    mapped_ = newMapped;

    // 写入数据
    InsertMapping(activeFields, headerSize, fieldsHeaderSize);

    index_[key].emplace_back(file_size_, totalSize);
    entryIndex_[entry] = lastAccessTime;

    file_size_ += totalSize;

    // 刷新到磁盘
    msync(mapped_, file_size_, MS_SYNC);

    return true;
}

bool StreamCacheManager::InsertMapping(const std::vector<std::pair<CacheFieldId, std::string>>& activeFields,
    size_t headerSize, size_t fieldsHeaderSize)
{
    CHECK_AND_RETURN_RET_LOG(mapped_ != MAP_FAILED, false, "mapped is invalid");
    char* ptr = static_cast<char*>(mapped_) + file_size_;
    CacheEntryHeader* header = reinterpret_cast<CacheEntryHeader*>(ptr);
    CHECK_AND_RETURN_RET_LOG(header != nullptr, false, "reinterpret_cast CacheEntryHeader is null");
    header->version = VERSION;
    header->fieldCount = FILED_COUNT;

    CacheField* fieldHeaders = reinterpret_cast<CacheField*>(ptr + sizeof(CacheEntryHeader));
    char* contentPtr = ptr + headerSize + fieldsHeaderSize;
    for (size_t i = 0; i < activeFields.size(); ++i) {
        fieldHeaders[i].id = static_cast<uint32_t>(activeFields[i].first);
        fieldHeaders[i].len = activeFields[i].second.size();
        memcpy_s(contentPtr, activeFields[i].second.size(),
            activeFields[i].second.data(), activeFields[i].second.size());
        contentPtr += activeFields[i].second.size();
    }
    return true;
}

std::string StreamCacheManager::GetMediaCache(const std::string& url)
{
    std::unique_lock<std::mutex> lock(mutex_);
    std::string key = std::to_string(std::hash<std::string>()(url));
    auto it = index_.find(key);
    CHECK_AND_RETURN_RET_LOG(it != index_.end(), "",
        " directory corresponding to the url does not exist");
    CacheEntryInfo info;
    CHECK_AND_RETURN_RET_LOG(FindFirstEqualField(it->second, info, url, CacheFieldId::REQUEST_URL),
        "", "directory corresponding to the url does not exist");
    CHECK_AND_RETURN_RET_LOG(mapped_ != MAP_FAILED, "", "mapped is invalid");
    char* ptr = static_cast<char*>(mapped_);
    CacheEntryHeader* header = reinterpret_cast<CacheEntryHeader*>(ptr + info.offset);
    std::string entry = ExtractField(ptr + info.offset, header->fieldCount, CacheFieldId::ENTRY);
    CHECK_AND_RETURN_RET_LOG(!entry.empty() && entry.find("..") == std::string::npos
        && entry.find('/') == std::string::npos && entry.find('\\') == std::string::npos,
        "", "get media cache file failed");
    
    std::string path = CACHE_DIR + fs::path::preferred_separator + entry;
    CreateDirectories(path.c_str());
    UpdateLastAccessTime(info, entry);

    return path;
}

bool StreamCacheManager::RemoveMediaCache(const std::string& url)
{
    std::string key = std::to_string(std::hash<std::string>()(url));
    auto it = index_.find(key);
    CHECK_AND_RETURN_RET_LOG(it != index_.end(), false, " directory corresponding to the url does not exist");

    // 向前移动
    CacheEntryInfo info;
    CHECK_AND_RETURN_RET_LOG(FindFirstEqualField(it->second, info, url, CacheFieldId::REQUEST_URL),
        false, "find url failed");
    CHECK_AND_RETURN_RET_LOG(mapped_ != MAP_FAILED, false, "mapped is invalid");
    char* ptr = static_cast<char*>(mapped_);
    CacheEntryHeader* header = reinterpret_cast<CacheEntryHeader*>(ptr + info.offset);
    std::string entry = ExtractField(ptr + info.offset, header->fieldCount, CacheFieldId::ENTRY);
    std::string path = CACHE_DIR + fs::path::preferred_separator + entry;
    fs::remove_all(path);
    MEDIA_LOGI("remove file:%{public}s", entry.c_str());
    errno_t ret = memmove_s(ptr + info.offset, file_size_ - info.offset, ptr + info.offset + info.cacheEntrySize,
        file_size_ - (info.offset + info.cacheEntrySize));
    CHECK_AND_RETURN_RET_LOG(ret == EOK, false, "remove media cache falied");

    file_size_ -= info.cacheEntrySize;
    ftruncate(fd_, file_size_);
    index_.clear();
    entryIndex_.clear();
    LoadIndex();

    return true;
}

bool StreamCacheManager::CreateDirectories(const std::string& path)
{
    CHECK_AND_RETURN_RET_LOG(!fs::exists(path) || !fs::is_directory(path), true, "directory exists");
    std::error_code ec;
    bool success = fs::create_directories(path, ec);
    CHECK_AND_RETURN_RET_LOG(success, false, "create_directories error:%{public}s", ec.message().c_str());
    return success;
}

uint64_t StreamCacheManager::ScanDirectorySize(const std::string& path)
{
    uint64_t totalSize = 0;
    CHECK_AND_RETURN_RET_LOG(fs::exists(path) && fs::is_directory(path), 0,
        "file not exist or is not directory");
    
    // 遍历目录及其子目录
    for (const auto& entry : fs::recursive_directory_iterator(path)) {
        // 检查文件是否为普通文件
        if (fs::is_regular_file(entry.status())) {
            totalSize += fs::file_size(entry);
        }
    }

    return totalSize;
}

bool StreamCacheManager::FindFirstEqualField(const std::vector<CacheEntryInfo>& entries,
    CacheEntryInfo& result, const std::string& value, CacheFieldId field)
{
    CHECK_AND_RETURN_RET_LOG(mapped_ != MAP_FAILED, false, "mapped is invalid");
    auto it = std::find_if(entries.begin(), entries.end(),
        [&](const CacheEntryInfo& info) {
            char* ptr = static_cast<char*>(mapped_);
            CacheEntryHeader* header = reinterpret_cast<CacheEntryHeader*>(ptr + info.offset);
            std::string target = ExtractField(ptr + info.offset, header->fieldCount, field);
            return target == value;
        });
    if (it != entries.end()) {
        result = *it;
        return true;
    }
    return false;
}

bool StreamCacheManager::UpdateLastAccessTime(CacheEntryInfo &info, const std::string& entry)
{
    CHECK_AND_RETURN_RET_LOG(mapped_ != MAP_FAILED, false, "mapped is invalid");
    char* ptr = static_cast<char*>(mapped_) + info.offset;
    CacheEntryHeader* header = reinterpret_cast<CacheEntryHeader*>(ptr);
    CacheField* fieldHeaders = reinterpret_cast<CacheField*>(ptr + sizeof(CacheEntryHeader));
    char* contentPtr = ptr + sizeof(CacheEntryHeader) + (header->fieldCount * sizeof(CacheField));

    size_t offset = 0;
    for (size_t i = 0; i < header->fieldCount; ++i) {
        if (fieldHeaders[i].id != static_cast<uint32_t>(CacheFieldId::LAST_ACCESS_TIME)) {
            offset += fieldHeaders[i].len;
            continue;
        }
        auto millisec_since_epoch = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
        std::string newTimeStr = std::to_string(millisec_since_epoch);

        entryIndex_[entry] = newTimeStr;
        CHECK_AND_RETURN_RET_LOG(fieldHeaders[i].len == newTimeStr.size(), true, "length is inconsistent");
        memcpy_s(contentPtr + offset, fieldHeaders[i].len, newTimeStr.data(), newTimeStr.size());
        msync(mapped_, file_size_, MS_SYNC);
        return true;
    }

    MEDIA_LOGE("LAST_ACCESS_TIME field not found in entry at offset:%zu", offset);
    return false;
}

std::string StreamCacheManager::GetPrefixBeforeUnderscore(const std::string& str)
{
    size_t pos = str.find('_');
    CHECK_AND_RETURN_RET_NOLOG(pos != std::string::npos, str);
    return str.substr(0, pos);
}

bool StreamCacheManager::RemoveCacheDirectory(const std::string& path)
{
    CHECK_AND_RETURN_RET_LOG(fs::exists(path) && fs::is_directory(path), false,
        "file does not exist or is not a directory");
    int removeSize = 0;
    int deletedCount = 0;
    std::vector<FileInfo> files;
    for (const auto& entry : fs::recursive_directory_iterator(path)) {
        if (fs::is_regular_file(entry.status())) {
            auto writeTime = fs::last_write_time(entry.path());
            uint64_t size = fs::file_size(entry.path());
            files.push_back({ entry.path(), writeTime, size });
        }
    }
    std::sort(files.begin(), files.end());

    for (const auto& file : files) {
        if (removeSize >= NEED_REMOVE_CACHE_SIZE) {
            MEDIA_LOGI("remove end, count:%{public}d, size:%{public}d", removeSize, deletedCount);
            break;
        }

        // 删除文件
        CHECK_AND_CONTINUE_LOG(fs::remove(file.path), "remove file failed");
        removeSize += file.size;
        deletedCount++;
        FlushCacheSize(removeSize);
    }
    return true;
}

void StreamCacheManager::FlushCacheSize(uint64_t size)
{
    if (cacheSize_.load() < size) {
        cacheSize_.store(0, std::memory_order_relaxed);
    } else {
        cacheSize_.fetch_sub(size, std::memory_order_relaxed);
    }
}
}
}