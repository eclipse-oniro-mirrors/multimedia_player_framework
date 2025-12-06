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

#include <queue>
#include <surface.h>
#include "screen_capture.h"

namespace OHOS::Media {
struct SurfaceBufferEntry {
    SurfaceBufferEntry(sptr<OHOS::SurfaceBuffer> buf, int32_t fence, int64_t timeStamp, OHOS::Rect& damage)
        : buffer(std::move(buf)), flushFence(fence), timeStamp(timeStamp), damageRect(damage) {}
    ~SurfaceBufferEntry() noexcept = default;

    sptr<OHOS::SurfaceBuffer> buffer;
    int32_t flushFence;
    int64_t timeStamp = 0;
    OHOS::Rect damageRect = {0, 0, 0, 0};
};

enum class SCBufferMessageType {
    EXIT,
    GET_BUFFER
};

struct SCBufferMessage {
    SCBufferMessageType type;
    std::string text;
};

class ScreenCapBufferConsumerListener : public IBufferConsumerListener {
public:
    ScreenCapBufferConsumerListener(
        sptr<Surface> consumer, const std::shared_ptr<ScreenCaptureCallBack> &screenCaptureCb)
        : consumer_(consumer), screenCaptureCb_(screenCaptureCb) {}
    ~ScreenCapBufferConsumerListener();

    void OnBufferAvailable() override;
    int32_t AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence, int64_t &timestamp,
        OHOS::Rect &damage);
    int32_t ReleaseVideoBuffer();
    int32_t Release();
    int32_t StartBufferThread();
    void OnBufferAvailableAction();
    void SurfaceBufferThreadRun();
    void StopBufferThread();

private:
    int32_t ReleaseBuffer();
    void ProcessVideoBufferCallBack();

private:
    std::mutex bufferAvailableWorkerMtx_;
    std::condition_variable bufferAvailableWorkerCv_;
    std::queue<SCBufferMessage> messageQueueSCB_;

    std::mutex mutex_;
    sptr<OHOS::Surface> consumer_ = nullptr;
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb_ = nullptr;
    std::atomic<bool> isSurfaceCbInThreadStopped_ {true};
    std::thread* surfaceCbInThread_ = nullptr;

    std::mutex bufferMutex_;
    std::condition_variable bufferCond_;
    std::queue<std::unique_ptr<SurfaceBufferEntry>> availBuffers_;

    static constexpr uint64_t MAX_MESSAGE_QUEUE_SIZE = 5;
    static constexpr uint32_t MAX_BUFFER_SIZE = 3;
    static constexpr uint32_t OPERATION_TIMEOUT_IN_MS = 1000; // 1000ms
};
}

#endif