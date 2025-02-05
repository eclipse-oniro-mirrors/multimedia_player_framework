/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef URI_HELPER_H
#define URI_HELPER_H

#include <cstdint>
#include <string>
#include <string_view>
#include <map>
#include <unistd.h>
#include <fcntl.h>
#include "nocopyable.h"

namespace OHOS {
namespace Media {
struct FdDesInfo {
    int32_t fd = 0;
    int64_t offset = 0;
    int64_t size = 0;
};

enum FdLocation : int32_t {
    INVALID = 0,
    LOCAL,
    CLOUD,
};

/**
 * The simple utility is designed to facilitate the uri processing.
 */
class __attribute__((visibility("default"))) UriHelper : public NoCopyable {
public:
    enum UriType : uint8_t {
        URI_TYPE_FILE,
        URI_TYPE_FD,
        URI_TYPE_HTTP,
        URI_TYPE_UNKNOWN,
    };

    enum UriAccessMode : uint8_t {
        URI_READ = 1 << 0,
        URI_WRITE = 1 << 1,
    };

    explicit UriHelper(const std::string_view &uri);
    UriHelper(int32_t fd, int64_t offset, int64_t size);
    ~UriHelper();

    uint8_t UriType() const;
    std::string FormattedUri() const;
    bool AccessCheck(uint8_t flag) const;

    FdDesInfo GetFdInfo()
    {
        return { .fd = fd_, .offset = offset_, .size = size_ };
    }

    FdLocation GetFdLocation();

private:
    void FormatMeForUri(const std::string_view &uri) noexcept;
    void FormatMeForFd() noexcept;
    bool ParseFdUri(std::string_view uri);
    bool CorrectFdParam();
    void DetermineFdLocation();

    std::string formattedUri_ = "";
    std::string_view rawFileUri_ = "";
    uint8_t type_ = 0;
    int32_t fd_ = -1;
    int64_t offset_ = 0;
    int64_t size_ = 0;
    FdLocation fdLocation_ = FdLocation::INVALID;
};
} // namespace Media
} // namespace OHOS

#endif