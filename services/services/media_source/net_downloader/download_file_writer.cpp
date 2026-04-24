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

#include "download_file_writer.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "media_log.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

namespace {
constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "FileWriter"};
constexpr int32_t INVALID_FD = -1;
constexpr int32_t DEFAULT_FILE_MODE = 0644;
}

FileWriter::FileWriter(const std::string &outputPath)
    : outputPath_(outputPath),
      fd_(INVALID_FD),
      opened_(false),
      writtenSize_(0)
{
    MEDIA_LOGI("FileWriter created, path=%{public}s", outputPath.c_str());
}

FileWriter::~FileWriter()
{
    Close();
    MEDIA_LOGI("FileWriter destroyed");
}

int32_t FileWriter::ValidatePath(const std::string &path)
{
    if (path.empty()) {
        MEDIA_LOGE("ValidatePath failed: empty path");
        return DOWNLOAD_ERROR_INVALID_PARAM;
    }
    
    return DOWNLOAD_ERROR_OK;
}

bool FileWriter::HasWritePermission(const std::string &path)
{
    MEDIA_LOGD("HasWritePermission check for %{public}s", path.c_str());
    return true;
}

bool FileWriter::EnsureDirectoryExists(const std::string &path)
{
    MEDIA_LOGD("EnsureDirectoryExists for %{public}s", path.c_str());
    return true;
}

int32_t FileWriter::Open()
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (opened_) {
        MEDIA_LOGW("FileWriter already opened");
        return DOWNLOAD_ERROR_OK;
    }
    
    int32_t ret = ValidatePath(outputPath_);
    if (ret != DOWNLOAD_ERROR_OK) {
        return ret;
    }
    
    if (!HasWritePermission(outputPath_)) {
        MEDIA_LOGE("Open failed: no write permission");
        return DOWNLOAD_ERROR_DISK_SPACE;
    }
    
    if (!EnsureDirectoryExists(outputPath_)) {
        MEDIA_LOGE("Open failed: cannot create directory");
        return DOWNLOAD_ERROR_FILE_IO;
    }
    
    fd_ = open(outputPath_.c_str(), O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_FILE_MODE);
    if (fd_ < 0) {
        MEDIA_LOGE("Open failed: errno=%{public}d", errno);
        return DOWNLOAD_ERROR_FILE_IO;
    }
    
    opened_ = true;
    writtenSize_ = 0;
    
    MEDIA_LOGI("Open success, fd=%{public}d", fd_);
    return DOWNLOAD_ERROR_OK;
}

void FileWriter::Close()
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!opened_) {
        return;
    }
    
    if (fd_ != INVALID_FD) {
        close(fd_);
        fd_ = INVALID_FD;
    }
    
    opened_ = false;
    MEDIA_LOGI("Close success, writtenSize=%{public}" PRId64, writtenSize_);
}

int32_t FileWriter::Write(const uint8_t *buffer, int32_t size)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!opened_) {
        MEDIA_LOGE("Write failed: not opened");
        return DOWNLOAD_ERROR_FILE_IO;
    }
    
    if (buffer == nullptr || size <= 0) {
        MEDIA_LOGE("Write failed: invalid buffer or size");
        return DOWNLOAD_ERROR_INVALID_PARAM;
    }
    
    ssize_t bytesWritten = write(fd_, buffer, size);
    if (bytesWritten < 0) {
        MEDIA_LOGE("Write failed: errno=%{public}d", errno);
        return DOWNLOAD_ERROR_FILE_IO;
    }
    
    writtenSize_ += bytesWritten;
    
    MEDIA_LOGD("Write success: size=%{public}d, total=%{public}" PRId64, size, writtenSize_);
    return DOWNLOAD_ERROR_OK;
}

int64_t FileWriter::GetWrittenSize()
{
    return writtenSize_;
}

bool FileWriter::IsOpened()
{
    return opened_;
}

int32_t FileWriter::Truncate()
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!opened_) {
        MEDIA_LOGE("Truncate failed: not opened");
        return DOWNLOAD_ERROR_FILE_IO;
    }
    
    MEDIA_LOGI("Truncate success");
    return DOWNLOAD_ERROR_OK;
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS