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

#ifndef SCREEN_CAP_BUFFER_CONSUMER_LISTENER_H
#define SCREEN_CAP_BUFFER_CONSUMER_LISTENER_H

#include "screen_capture.h"
#include <memory>
#include <queue>
#include <surface.h>

namespace OHOS::Media {
enum class SCBufferMessageType { EXIT, NOTIFY };

struct SCBufferMessage {
    SCBufferMessageType type;
};

class ScreenCapBufferConsumerListener : public IBufferConsumerListener {
public:
    ScreenCapBufferConsumerListener(sptr<Surface> consumer,
        const std::shared_ptr<ScreenCaptureCallBack> &screenCaptureCb)
        : consumer_(consumer), screenCaptureCb_(screenCaptureCb)
    {
    }
    ~ScreenCapBufferConsumerListener();

    void OnBufferAvailable() override;
    int32_t AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence, int64_t &timestamp,
        OHOS::Rect &damage);
    int32_t ReleaseVideoBuffer();
    int32_t StartBufferThread();
    void StopBufferThread();
    void SetCallback(const std::shared_ptr<ScreenCaptureCallBack> &screenCaptureCb);

private:
    void NotifyThreadRun();

    std::mutex notifyMtx_;
    std::condition_variable notifyCv_;
    std::queue<SCBufferMessage> messageQueue_;

    std::mutex mutex_;
    sptr<OHOS::Surface> consumer_ = nullptr;
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb_ = nullptr;
    sptr<OHOS::SurfaceBuffer> currentBuffer_ = nullptr;

    std::unique_ptr<std::thread> notifyThread_;

    static constexpr uint64_t MAX_MESSAGE_QUEUE_SIZE = 5;
    static constexpr int32_t FENCE_WAIT_MS = 1000;
};
} // namespace OHOS::Media

#endif
