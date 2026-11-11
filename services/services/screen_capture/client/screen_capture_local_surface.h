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

#ifndef SCREEN_CAPTURE_LOCAL_SURFACE_H
#define SCREEN_CAPTURE_LOCAL_SURFACE_H

#include "screen_cap_buffer_consumer_listener.h"
#include "screen_capture.h"
#include <mutex>
#include <surface.h>

namespace OHOS {
namespace Media {
class ScreenCaptureLocalSurface {
public:
    ScreenCaptureLocalSurface() = default;
    ~ScreenCaptureLocalSurface();

    ScreenCaptureLocalSurface(const ScreenCaptureLocalSurface &) = delete;
    ScreenCaptureLocalSurface &operator=(const ScreenCaptureLocalSurface &) = delete;

    int32_t Init(const std::shared_ptr<ScreenCaptureCallBack> &callback);
    void SetCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback);
    sptr<Surface> GetProducerSurface() const;
    int32_t AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence, int64_t &timestamp,
        OHOS::Rect &damage);
    int32_t ReleaseVideoBuffer();

private:
    mutable std::mutex mutex_;
    sptr<OHOS::Surface> consumer_ = nullptr;
    sptr<OHOS::Surface> producerSurface_ = nullptr;
    sptr<ScreenCapBufferConsumerListener> surfaceCb_ = nullptr;
};
} // namespace Media
} // namespace OHOS

#endif // SCREEN_CAPTURE_LOCAL_SURFACE_H
