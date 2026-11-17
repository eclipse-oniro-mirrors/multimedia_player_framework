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

#ifndef NATIVE_AVSCREEN_CAPTURE_IMPL_H
#define NATIVE_AVSCREEN_CAPTURE_IMPL_H

#include <atomic>
#include <memory>
#include <mutex>
#include <queue>
#include <refbase.h>
#include <surface/window.h>

#include "native_window.h"
#include "screen_capture.h"

struct OH_AVScreenCapture : public OHOS::RefBase {
    OH_AVScreenCapture() = default;
    ~OH_AVScreenCapture() override = default;
};

struct OH_AVScreenCapture_ContentFilter : public OHOS::RefBase {
    OH_AVScreenCapture_ContentFilter() = default;
    ~OH_AVScreenCapture_ContentFilter() override = default;
};

struct OH_AVScreenCapture_CaptureStrategy : public OHOS::RefBase {
    OH_AVScreenCapture_CaptureStrategy() = default;
    ~OH_AVScreenCapture_CaptureStrategy() override = default;
};

struct OH_AVScreenCapture_UserSelectionInfo : public OHOS::RefBase {
    OH_AVScreenCapture_UserSelectionInfo() = default;
    ~OH_AVScreenCapture_UserSelectionInfo() override = default;
};

struct NativeBufferRef {
    NativeBufferRef() noexcept = default;
    ~NativeBufferRef() noexcept
    {
        if (buf_ != nullptr) {
            OH_NativeBuffer_Unreference(buf_);
        }
    }
    NativeBufferRef(const NativeBufferRef &) = delete;
    NativeBufferRef &operator=(const NativeBufferRef &) = delete;
    NativeBufferRef(NativeBufferRef &&o) noexcept : buf_(o.buf_)
    {
        o.buf_ = nullptr;
    }
    NativeBufferRef &operator=(NativeBufferRef &&o) noexcept
    {
        if (this != &o) {
            if (buf_ != nullptr) {
                OH_NativeBuffer_Unreference(buf_);
            }
            buf_ = o.buf_;
            o.buf_ = nullptr;
        }
        return *this;
    }
    static NativeBufferRef Acquire(OH_NativeBuffer *buf) noexcept
    {
        NativeBufferRef r;
        if (OH_NativeBuffer_Reference(buf) == 0) {
            r.buf_ = buf;
        }
        return r;
    }
    OH_NativeBuffer *get() const noexcept
    {
        return buf_;
    }
    OH_NativeBuffer *release() noexcept
    {
        auto b = buf_;
        buf_ = nullptr;
        return b;
    }
    explicit operator bool() const noexcept
    {
        return buf_ != nullptr;
    }

private:
    OH_NativeBuffer *buf_ = nullptr;
};

namespace OHOS {
namespace Media {
class NativeScreenCaptureCallback;

struct ScreenCaptureObject : public OH_AVScreenCapture, public std::enable_shared_from_this<ScreenCaptureObject> {
    explicit ScreenCaptureObject(const std::shared_ptr<ScreenCapture> &capture) : screenCapture_(capture) {}
    ~ScreenCaptureObject() = default;

    const std::shared_ptr<ScreenCapture> screenCapture_ = nullptr;
    std::mutex callbackMutex;
    std::shared_ptr<NativeScreenCaptureCallback> callback_ = nullptr;
    std::atomic<bool> isStart{false};

    std::mutex bufferMutex;
    std::queue<NativeBufferRef> referencedBuffer_;
};

struct ScreenCaptureUserSelectionObject : public OH_AVScreenCapture_UserSelectionInfo {
    explicit ScreenCaptureUserSelectionObject(ScreenCaptureUserSelectionInfo selectionInfo)
        : userSelectionInfo_(selectionInfo)
    {
    }
    ~ScreenCaptureUserSelectionObject() = default;
    ScreenCaptureUserSelectionInfo userSelectionInfo_;
};
} // namespace Media
} // namespace OHOS

#endif // NATIVE_AVSCREEN_CAPTURE_IMPL_H
