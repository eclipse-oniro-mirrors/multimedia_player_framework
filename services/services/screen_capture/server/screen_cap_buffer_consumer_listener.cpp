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

#include <sync_fence.h>
#include "media_dfx.h"
#include "media_log.h"
#include "screen_cap_buffer_consumer_listener.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCapBufferConsumerListener"};
}

namespace OHOS::Media {
void ScreenCapBufferConsumerListener::OnBufferAvailable()
{
    MediaTrace trace("ScreenCapConsumer::OnBufferAvailable", HITRACE_LEVEL_DEBUG);
    MEDIA_LOGD("ScreenCapConsumer: 0x%{public}06" PRIXPTR " OnBufferAvailable start.", FAKE_POINTER(this));
    {
        std::lock_guard<std::mutex> lock(bufferAvailableWorkerMtx_);
        messageQueueSCB_.push({SCBufferMessageType::GET_BUFFER, "Get buffer!"});
        MEDIA_LOGD("ScreenCapConsumer: 0x%{public}06" PRIXPTR " queue size: %{public}" PRId64, FAKE_POINTER(this),
            static_cast<uint64_t>(messageQueueSCB_.size()));
        bufferAvailableWorkerCv_.notify_one();
    }
}

void ScreenCapBufferConsumerListener::OnBufferAvailableAction()
{
    MediaTrace trace("ScreenCapConsumer::OnBufferAvailableAction", HITRACE_LEVEL_DEBUG);
    MEDIA_LOGD("OnBufferAvailableAction: 0x%{public}06" PRIXPTR " start.", FAKE_POINTER(this));
    CHECK_AND_RETURN(consumer_ != nullptr);
    int64_t timestamp = 0;
    OHOS::Rect damage;
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
    sptr<SyncFence> acquireFence = SyncFence::INVALID_FENCE;
    int32_t acquireBufferRet = consumer_->AcquireBuffer(buffer, acquireFence, timestamp, damage);
    if (acquireBufferRet != GSERROR_OK) {
        MEDIA_LOGE("OnBufferAvailableAction AcquireBuffer Fail Code %{public}d", acquireBufferRet);
    }
    MEDIA_LOGD("OnBufferAvailableAction: 0x%{public}06" PRIXPTR " after AcquireBuffer.", FAKE_POINTER(this));
    int32_t flushFence = -1;
    if (acquireFence != nullptr && acquireFence != SyncFence::INVALID_FENCE) {
        acquireFence->Wait(1000); // 1000 ms
        flushFence = acquireFence->Get();
    }
    CHECK_AND_RETURN_LOG(buffer != nullptr, "Acquire SurfaceBuffer failed");
    if ((buffer->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE) != 0) {
        MEDIA_LOGD("OnBufferAvailableAction cache enable");
        buffer->InvalidateCache();
    }
    void *addr = buffer->GetVirAddr();
    if (addr == nullptr) {
        MEDIA_LOGE("Acquire SurfaceBuffer address invalid");
        int32_t releaseBufferRet = consumer_->ReleaseBuffer(buffer, -1); // -1 not wait
        if (releaseBufferRet != GSERROR_OK) {
            MEDIA_LOGE("OnBufferAvailableAction: 0x%{public}06" PRIXPTR " ReleaseBuffer Fail Code %{public}d",
                FAKE_POINTER(this), releaseBufferRet);
        }
        return;
    }
    MEDIA_LOGD("OnBufferAvailableAction SurfaceBuffer size: %{public}u", buffer->GetSize());
    {
        std::unique_lock<std::mutex> lock(bufferMutex_);
        if (availBuffers_.size() > MAX_BUFFER_SIZE) {
            MEDIA_LOGE("OnBufferAvailableAction consume slow, drop video frame");
            int32_t releaseBufferRet = consumer_->ReleaseBuffer(buffer, -1); // -1 not wait
            if (releaseBufferRet != GSERROR_OK) {
                MEDIA_LOGE("OnBufferAvailableAction: 0x%{public}06" PRIXPTR " consume slow ReleaseBuffer "
                    "Fail Code %{public}d", FAKE_POINTER(this), releaseBufferRet);
            }
            return;
        }
        availBuffers_.push(std::make_unique<SurfaceBufferEntry>(buffer, flushFence, timestamp, damage));
    }
    bufferCond_.notify_all();
    ProcessVideoBufferCallBack();
}

void ScreenCapBufferConsumerListener::SurfaceBufferThreadRun()
{
    SCBufferMessage message;
    std::string threadName = std::string("OS_SCBufferAvailableWorker");
    MEDIA_LOGD("0x%{public}06" PRIXPTR " BufferAvailableWorker name: %{public}s",
        FAKE_POINTER(this), threadName.c_str());
    pthread_setname_np(pthread_self(), threadName.c_str());
    while (true) {
        {
            std::unique_lock<std::mutex> lock(bufferAvailableWorkerMtx_);
            bufferAvailableWorkerCv_.wait(lock, [&]() { return !messageQueueSCB_.empty(); });
            message = messageQueueSCB_.front();
            if (static_cast<uint64_t>(messageQueueSCB_.size()) > MAX_MESSAGE_QUEUE_SIZE &&
                message.type == SCBufferMessageType::GET_BUFFER) {
                messageQueueSCB_.pop();
                MEDIA_LOGE("0x%{public}06" PRIXPTR " BufferAvailableWorker skip get buffer", FAKE_POINTER(this));
                continue;
            }
            messageQueueSCB_.pop();
        }
        if (message.type == SCBufferMessageType::EXIT) {
            break;
        }
        if (message.type == SCBufferMessageType::GET_BUFFER) {
            OnBufferAvailableAction();
        }
    }
    MEDIA_LOGD("ScreenCapBufferConsumerListener::SurfaceBufferThreadRun End.");
}

int32_t ScreenCapBufferConsumerListener::StartBufferThread()
{
    if (isSurfaceCbInThreadStopped_.load()) {
        surfaceCbInThread_ = new (std::nothrow) std::thread([this]() {
            isSurfaceCbInThreadStopped_.store(false);
            this->SurfaceBufferThreadRun();
            isSurfaceCbInThreadStopped_.store(true);
        });
        CHECK_AND_RETURN_RET_LOG(surfaceCbInThread_ != nullptr, MSERR_UNKNOWN, "new surface thread failed");
    }
    MEDIA_LOGI("ScreenCapBufferConsumerListener::StartBufferThread End.");
    return MSERR_OK;
}

void ScreenCapBufferConsumerListener::ProcessVideoBufferCallBack()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(screenCaptureCb_ != nullptr, "no consumer, will drop video frame");
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " OnBufferAvailable end.", FAKE_POINTER(this));
    screenCaptureCb_->OnVideoBufferAvailable(true);
}

int32_t ScreenCapBufferConsumerListener::AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
    int64_t &timestamp, OHOS::Rect &damage)
{
    MediaTrace trace("ScreenCaptureServer::AcquireVideoBuffer", HITRACE_LEVEL_DEBUG);
    using namespace std::chrono_literals;
    std::unique_lock<std::mutex> lock(bufferMutex_);
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " AcquireVideoBuffer start, fence:%{public}d, "
        "timestamp:%{public}" PRId64, FAKE_POINTER(this), fence, timestamp);
    if (!bufferCond_.wait_for(
        lock, std::chrono::milliseconds(OPERATION_TIMEOUT_IN_MS), [this] { return !availBuffers_.empty(); })) {
        return MSERR_UNKNOWN;
    }
    surfaceBuffer = availBuffers_.front()->buffer;
    fence = availBuffers_.front()->flushFence;
    timestamp = availBuffers_.front()->timeStamp;
    damage = availBuffers_.front()->damageRect;
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " AcquireVideoBuffer end.", FAKE_POINTER(this));
    return MSERR_OK;
}

void ScreenCapBufferConsumerListener::StopBufferThread()
{
    std::lock_guard<std::mutex> lock(bufferAvailableWorkerMtx_);
    messageQueueSCB_.push({SCBufferMessageType::EXIT, ""});
    MEDIA_LOGI("StopBufferThread: 0x%{public}06" PRIXPTR " EXIT.", FAKE_POINTER(this));
    bufferAvailableWorkerCv_.notify_one();
}

ScreenCapBufferConsumerListener::~ScreenCapBufferConsumerListener()
{
    MEDIA_LOGD("ScreenCapBufferConsumerListener: 0x%{public}06" PRIXPTR " Destroy.", FAKE_POINTER(this));
    StopBufferThread();
    if (surfaceCbInThread_ && surfaceCbInThread_->joinable()) {
        surfaceCbInThread_->join();
        delete surfaceCbInThread_;
        surfaceCbInThread_ = nullptr;
    }
    std::unique_lock<std::mutex> lock(bufferMutex_);
    ReleaseBuffer();
}

int32_t ScreenCapBufferConsumerListener::ReleaseBuffer()
{
    while (!availBuffers_.empty()) {
        if (consumer_ != nullptr) {
            int32_t releaseBufferRet = consumer_->ReleaseBuffer(availBuffers_.front()->buffer, -1);  // -1 not wait
            if (releaseBufferRet != GSERROR_OK) {
                MEDIA_LOGE("ScreenCapBufferConsumerListener: 0x%{public}06" PRIXPTR " ReleaseBuffer "
                    "Fail Code %{public}d", FAKE_POINTER(this), releaseBufferRet);
            }
        }
        availBuffers_.pop();
    }
    return MSERR_OK;
}

int32_t ScreenCapBufferConsumerListener::ReleaseVideoBuffer()
{
    MediaTrace trace("ScreenCaptureServer::ReleaseVideoBuffer", HITRACE_LEVEL_DEBUG);
    std::unique_lock<std::mutex> lock(bufferMutex_);
    MEDIA_LOGD("ScreenCapBufferConsumerListener: 0x%{public}06" PRIXPTR " ReleaseVideoBuffer start.",
        FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(!availBuffers_.empty(), MSERR_OK, "buffer queue is empty, no video frame to release");

    if (consumer_ != nullptr) {
        int32_t releaseBufferRet = consumer_->ReleaseBuffer(availBuffers_.front()->buffer, -1); // -1 not wait
        if (releaseBufferRet != GSERROR_OK) {
            MEDIA_LOGE("ScreenCapBufferConsumerListener: 0x%{public}06" PRIXPTR " ReleaseVideoBuffer "
                "Fail Code %{public}d", FAKE_POINTER(this), releaseBufferRet);
        }
    }
    availBuffers_.pop();
    MEDIA_LOGD("ScreenCapBufferConsumerListener: 0x%{public}06" PRIXPTR " ReleaseVideoBuffer end.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCapBufferConsumerListener::Release()
{
    std::unique_lock<std::mutex> lock(bufferMutex_);
    MEDIA_LOGI("ScreenCapBufferConsumerListener Release");
    return ReleaseBuffer();
}
}