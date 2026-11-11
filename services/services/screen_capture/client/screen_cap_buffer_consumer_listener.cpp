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

#include "screen_cap_buffer_consumer_listener.h"
#include "media_errors.h"
#include "media_log.h"
#include <sync_fence.h>

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCapBufferConsumerListener"};
}

namespace OHOS::Media {
void ScreenCapBufferConsumerListener::OnBufferAvailable()
{
    {
        std::lock_guard<std::mutex> lock(notifyMtx_);
        if (messageQueue_.size() > MAX_MESSAGE_QUEUE_SIZE) {
            MEDIA_LOGE("0x%{public}06" PRIXPTR " notify queue full, skip", FAKE_POINTER(this));
            return;
        }
        messageQueue_.push({SCBufferMessageType::NOTIFY});
    }
    notifyCv_.notify_one();
}

void ScreenCapBufferConsumerListener::NotifyThreadRun()
{
    pthread_setname_np(pthread_self(), "OS_SCBufferNotify");
    SCBufferMessage msg;
    while (true) {
        {
            std::unique_lock<std::mutex> lock(notifyMtx_);
            notifyCv_.wait(lock, [this] { return !messageQueue_.empty(); });
            msg = messageQueue_.front();
            messageQueue_.pop();
        }
        if (msg.type == SCBufferMessageType::EXIT) {
            break;
        }
        if (msg.type == SCBufferMessageType::NOTIFY) {
            std::shared_ptr<ScreenCaptureCallBack> cb;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                cb = screenCaptureCb_;
            }
            if (cb != nullptr) {
                cb->OnVideoBufferAvailable(true);
            }
        }
    }
    MEDIA_LOGD("ScreenCapBufferConsumerListener::NotifyThreadRun End.");
}

int32_t ScreenCapBufferConsumerListener::StartBufferThread()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (notifyThread_ != nullptr && notifyThread_->joinable()) {
        return MSERR_OK;
    }
    notifyThread_ = std::make_unique<std::thread>([this]() { this->NotifyThreadRun(); });
    return MSERR_OK;
}

void ScreenCapBufferConsumerListener::StopBufferThread()
{
    std::lock_guard<std::mutex> lock(notifyMtx_);
    messageQueue_.push({SCBufferMessageType::EXIT});
    MEDIA_LOGI("StopBufferThread: 0x%{public}06" PRIXPTR " EXIT.", FAKE_POINTER(this));
    notifyCv_.notify_one();
}

void ScreenCapBufferConsumerListener::SetCallback(const std::shared_ptr<ScreenCaptureCallBack> &screenCaptureCb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    screenCaptureCb_ = screenCaptureCb;
}

ScreenCapBufferConsumerListener::~ScreenCapBufferConsumerListener()
{
    MEDIA_LOGD("ScreenCapBufferConsumerListener: 0x%{public}06" PRIXPTR " Destroy.", FAKE_POINTER(this));
    {
        std::lock_guard<std::mutex> lock(mutex_);
        screenCaptureCb_ = nullptr;
    }
    StopBufferThread();
    std::unique_ptr<std::thread> thread;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        thread = std::move(notifyThread_);
    }
    if (thread != nullptr && thread->joinable()) {
        thread->join();
    }
    sptr<OHOS::SurfaceBuffer> buf;
    sptr<OHOS::Surface> consumer;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        buf = currentBuffer_;
        currentBuffer_ = nullptr;
        consumer = consumer_;
    }
    if (buf != nullptr && consumer != nullptr) {
        consumer->ReleaseBuffer(buf, -1);
    }
}

int32_t ScreenCapBufferConsumerListener::AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
    int64_t &timestamp, OHOS::Rect &damage)
{
    CHECK_AND_RETURN_RET_LOG(consumer_ != nullptr, MSERR_INVALID_OPERATION, "consumer is nullptr");
    sptr<SyncFence> acquireFence = SyncFence::INVALID_FENCE;
    int32_t ret = consumer_->AcquireBuffer(surfaceBuffer, acquireFence, timestamp, damage);
    CHECK_AND_RETURN_RET_LOG(ret == GSERROR_OK, MSERR_UNKNOWN, "AcquireBuffer failed, ret:%{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(surfaceBuffer != nullptr, MSERR_UNKNOWN, "AcquireBuffer returns null buffer");

    int32_t flushFence = -1;
    if (acquireFence != nullptr && acquireFence != SyncFence::INVALID_FENCE) {
        acquireFence->Wait(FENCE_WAIT_MS);
        flushFence = acquireFence->Get();
    }
    if ((surfaceBuffer->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE) != 0) {
        surfaceBuffer->InvalidateCache();
    }
    fence = flushFence;
    sptr<OHOS::SurfaceBuffer> buf;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        buf = currentBuffer_;
        currentBuffer_ = surfaceBuffer;
    }
    if (buf != nullptr && consumer_ != nullptr) {
        consumer_->ReleaseBuffer(buf, -1);
    }
    MEDIA_LOGD("AcquireVideoBuffer end, size:%{public}u", surfaceBuffer->GetSize());
    return MSERR_OK;
}

int32_t ScreenCapBufferConsumerListener::ReleaseVideoBuffer()
{
    sptr<OHOS::SurfaceBuffer> buf;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        buf = currentBuffer_;
        currentBuffer_ = nullptr;
    }
    CHECK_AND_RETURN_RET_LOG(buf != nullptr, MSERR_INVALID_OPERATION, "no video frame to release");
    CHECK_AND_RETURN_RET_LOG(consumer_ != nullptr, MSERR_INVALID_OPERATION, "consumer is nullptr");
    int32_t ret = consumer_->ReleaseBuffer(buf, -1); // -1 not wait
    CHECK_AND_RETURN_RET_LOG(ret == GSERROR_OK, MSERR_UNKNOWN, "ReleaseBuffer failed, ret:%{public}d", ret);
    return MSERR_OK;
}
} // namespace OHOS::Media
