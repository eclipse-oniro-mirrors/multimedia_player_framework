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

#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "file_cache_manager.h"
#include "cache_mapping_format.h"
#include "common/log.h"
#include "media_log.h"
#include "path_validator.h"

namespace OHOS {
namespace Media {
namespace DownloadedCache {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "DownloadedFileCacheManager"};
const char FILE_SEPARATOR = std::filesystem::path::preferred_separator;
}

DownloadedFileCacheManager::DownloadedFileCacheManager(const std::string& cacheDir)
    : cacheDir_(cacheDir)
{
}

std::shared_ptr<DownloadedFileCacheManager> DownloadedFileCacheManager::Create(const std::string& cacheDir)
{
    return std::make_shared<DownloadedFileCacheManager>(cacheDir);
}

int32_t DownloadedFileCacheManager::Read(const std::string& path, void* buffer, int64_t offset, int64_t size)
{
    FALSE_RETURN_V_MSG_E(IsValidPath(path), -1, "invalid path");
    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        MEDIA_LOG_W("ReadCacheData open file error");
        return -1;
    }

    struct stat buf;
    if (fstat(fd, &buf) != 0) {
        close(fd);
        MEDIA_LOG_E("ReadCacheData GetFileSize error");
        return -1;
    }

    if (buf.st_size < offset + size) {
        MEDIA_LOG_W("buffer size is not enough");
    }

    if (lseek(fd, offset, SEEK_SET) == -1) {
        close(fd);
        MEDIA_LOG_E("ReadCacheData lseek error");
        return -1;
    }

    int readSize = read(fd, buffer, size);
    close(fd);
    if (readSize < size) {
        MEDIA_LOG_W("ReadCacheData read error");
    }
    return 0;
}

int64_t DownloadedFileCacheManager::GetSize(const std::string& path)
{
    FALSE_RETURN_V_MSG_E(IsValidPath(path), -1, "invalid path");
    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        MEDIA_LOG_E("GetFileSize open file error");
        return -1;
    }

    struct stat buf;
    if (fstat(fd, &buf) != 0) {
        close(fd);
        MEDIA_LOG_E("GetFileSize fstat error");
        return -1;
    }
    close(fd);
    return buf.st_size;
}

bool DownloadedFileCacheManager::IsValidPath(const std::string& inputPath)
{
    if (inputPath.length() > PATH_MAX) {
        MEDIA_LOG_E("path len invalid");
        return false;
    }

    std::string relativePath;
    if (inputPath.length() > cacheDir_.length() && 
        inputPath.compare(0, cacheDir_.length(), cacheDir_) == 0) {
        relativePath = inputPath.substr(cacheDir_.length());
        if (!relativePath.empty() && relativePath[0] == FILE_SEPARATOR) {
            relativePath = relativePath.substr(1);
        }
    } else {
        MEDIA_LOG_E("path is not under the expected dir");
        return false;
    }

    if (relativePath.empty()) {
        return true;
    }

    return PathValidator::Validate(cacheDir_, relativePath);
}
} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS