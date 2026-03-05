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

#include <filesystem>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "file_cache_manager.h"
#include "common/log.h"

namespace OHOS {
namespace Media {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "FileCacheManager"};
    const std::string CACHE_DIR = "/data/storage/el2/base/cache/avplayer_media_loader";
    const char FILE_SEPARATOR = std::filesystem::path::preferred_separator;
}

std::shared_ptr<FileCacheManager> FileCacheManager::Create()
{
    return std::make_shared<FileCacheManager>();
}

int32_t FileCacheManager::Write(const std::string& path, const void* buffer, int64_t size)
{
    FALSE_RETURN_V_MSG_E(IsValidPath(path), -1, "invalid path");
    int fd = open(path.c_str(), O_RDWR | O_CREAT | O_APPEND, 0644);
    if (fd == -1) {
        MEDIA_LOG_E("WriteCacheData open file error");
        return -1;
    }
    int written = write(fd, buffer, size);
    close(fd);
    if (written < size) {
        MEDIA_LOG_E("WriteCacheData write error");
        return -1;
    }
    return 0;
}

int32_t FileCacheManager::Read(const std::string& path, void* buffer, int64_t offset, int64_t size)
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

int64_t FileCacheManager::GetSize(const std::string& path)
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

int32_t FileCacheManager::Clear(const std::string& path)
{
    int ret = unlink(path.c_str());
    if (ret == -1) {
        MEDIA_LOG_W("ClearCacheData unlink error");
        return -1;
    }
    return 0;
}

bool FileCacheManager::IsValid(const std::string& path, int64_t exceptedSize)
{
    int64_t actual = GetSize(path);
    if (actual != exceptedSize) {
        Clear(path);
        MEDIA_LOG_D("Segment is invalid: excepted %lld, got %lld", exceptedSize, actual);
        return false;
    }
    return true;
}

bool FileCacheManager::IsValidPath(const std::string& inputPath)
{
    FALSE_RETURN_V_MSG_E(inputPath.length() <= PATH_MAX, false, "path len invalid");

    std::filesystem::path inPath(inputPath);
    FALSE_RETURN_V_MSG_E(inPath.has_parent_path(), false, "path no parent path.");

    // if path not exist, check parent path
    auto checkPath = std::filesystem::exists(inputPath) ? inputPath : inPath.parent_path().string();

    char path[PATH_MAX + 1] = {0};
    auto realPath = realpath(checkPath.c_str(), path);
    FALSE_RETURN_V_MSG_E(realPath, false, "realPath fail");
    std::string canonicalPath(path);
    auto isPrefixValid = canonicalPath.length() >= CACHE_DIR.length() &&
        (canonicalPath.compare(0, CACHE_DIR.length(), CACHE_DIR) == 0) &&
        (canonicalPath.length() == CACHE_DIR.length() || canonicalPath[CACHE_DIR.length()] == FILE_SEPARATOR);
    FALSE_RETURN_V_MSG_E(isPrefixValid, false, "path is not under the expected dir");
    return true;
}
} // namespace Media
} // namespace OHOS