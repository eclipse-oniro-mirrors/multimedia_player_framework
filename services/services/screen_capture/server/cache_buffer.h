/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SCREEN_CAPTURE_CACHE_BUFFER_H
#define SCREEN_CAPTURE_CACHE_BUFFER_H

#include <cstdlib>
#include <memory>

#include "buffer/avbuffer.h"
#include "screen_capture.h"
#include "securec.h"

namespace OHOS {
namespace Media {

class CacheBuffer {
public:
    CacheBuffer() = delete;

    explicit CacheBuffer(std::unique_ptr<uint8_t[]> buf, int32_t len, int64_t ts,
        AudioCaptureSourceType type = AudioCaptureSourceType::SOURCE_DEFAULT)
        : length(len), timestamp(ts), sourcetype(type), ownedBuf_(std::move(buf))
    {
    }

    bool WriteTo(const std::shared_ptr<AVMemory> &mem, uint32_t len)
    {
        if (ownedBuf_ == nullptr) {
            return false;
        }
        mem->Write(ownedBuf_.get(), len, 0);
        return true;
    }

    bool WriteTo(std::shared_ptr<AudioBuffer> &audioBuffer)
    {
        if (ownedBuf_ == nullptr) {
            audioBuffer = std::make_shared<AudioBuffer>(nullptr, length, timestamp, sourcetype);
            return true;
        }
        uint8_t *copy = static_cast<uint8_t *>(malloc(length));
        if (copy == nullptr) {
            return false;
        }
        if (memcpy_s(copy, length, ownedBuf_.get(), length) != EOK) {
            free(copy);
            return false;
        }
        audioBuffer = std::make_shared<AudioBuffer>(copy, length, timestamp, sourcetype);
        return true;
    }

    int32_t length{0};
    int64_t timestamp{0};
    AudioCaptureSourceType sourcetype{AudioCaptureSourceType::SOURCE_DEFAULT};

    const uint8_t *Data() const
    {
        return ownedBuf_.get();
    }

private:
    std::unique_ptr<uint8_t[]> ownedBuf_;
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_CACHE_BUFFER_H
