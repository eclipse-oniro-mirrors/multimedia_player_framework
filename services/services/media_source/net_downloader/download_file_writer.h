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

#ifndef DOWNLOAD_FILE_WRITER_H
#define DOWNLOAD_FILE_WRITER_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "downloader.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

class FileWriter : public NoCopyable {
public:
    FileWriter(const std::string &outputPath);
    ~FileWriter();

    int32_t Open();
    void Close();
    int32_t Write(const uint8_t *buffer, int32_t size);
    int64_t GetWrittenSize();
    bool IsOpened();
    int32_t Truncate();

private:
    int32_t ValidatePath(const std::string &path);
    bool HasWritePermission(const std::string &path);
    bool EnsureDirectoryExists(const std::string &path);

    std::string outputPath_;
    int32_t fd_;
    bool opened_;
    int64_t writtenSize_;
    std::mutex mutex_;
};

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // DOWNLOAD_FILE_WRITER_H