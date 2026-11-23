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
#include <pthread.h>
#include <sync_fence.h>

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCapBufferConsumerListener"};
}

namespace OHOS::Media {
ScreenCapBufferConsumerListener::ScreenCapBufferConsumerListener(sptr<Surface> consumer,
    const std::shared_ptr<ScreenCaptureCallBack> &screenCaptureCb)
    : consumer_(consumer)
{
    std::lock_guard<std::mutex> lock(ctx_->mtx);
    ctx_->callback = screenCaptureCb;
}

void ScreenCapBufferConsumerListener::OnBufferAvailable()
{
    std::shared_ptr<NotifyContext> ctx = ctx_;
    {
        std::lock_guard<std::mutex> lock(ctx->mtx);
        if (!ctx->IsRunning()) {
            return;
        }
        if (ctx->pendingCount > MAX_MESSAGE_QUEUE_SIZE) {
            MEDIA_LOGE("0x%{public}06" PRIXPTR " notify queue full, skip", FAKE_POINTER(this));
            return;
        }
        ++ctx->pendingCount;
    }
    ctx->cv.notify_one();
}

void ScreenCapBufferConsumerListener::NotifyThreadRun(std::shared_ptr<NotifyContext> ctx)
{
    pthread_setname_np(pthread_self(), "OS_SCBufNotify");
    while (true) {
        std::shared_ptr<ScreenCaptureCallBack> cb;
        {
            std::unique_lock<std::mutex> lock(ctx->mtx);
            ctx->cv.wait(lock, [&ctx] {
                return ctx->state == NotifyContext::State::EXITING || (ctx->IsRunning() && ctx->pendingCount > 0);
            });
            if (ctx->state == NotifyContext::State::EXITING) {
                break;
            }
            if (!ctx->IsRunning() || ctx->pendingCount == 0) {
                continue;
            }
            --ctx->pendingCount;
            cb = ctx->callback;
        }
        if (cb != nullptr) {
            cb->OnVideoBufferAvailable(true);
        }
    }
    MEDIA_LOGD("ScreenCapBufferConsumerListener::NotifyThreadRun End.");
}

int32_t ScreenCapBufferConsumerListener::StartBufferThread()
{
    std::shared_ptr<NotifyContext> ctx = ctx_;
    std::lock_guard<std::mutex> lock(ctx->mtx);
    if (ctx->state == NotifyContext::State::EXITING) {
        return MSERR_INVALID_OPERATION;
    }
    if (ctx->thread != nullptr && ctx->IsRunning()) {
        return MSERR_OK;
    }
    if (ctx->thread == nullptr) {
        ctx->thread = std::make_unique<std::thread>([ctx]() { ScreenCapBufferConsumerListener::NotifyThreadRun(ctx); });
        MEDIA_LOGI("StartBufferThread: 0x%{public}06" PRIXPTR " started.", FAKE_POINTER(this));
    }
    ctx->state = NotifyContext::State::RUNNING;
    ctx->pendingCount = 0;
    ctx->cv.notify_all();
    return MSERR_OK;
}

void ScreenCapBufferConsumerListener::StopBufferThread()
{
    std::shared_ptr<NotifyContext> ctx = ctx_;
    {
        std::lock_guard<std::mutex> lock(ctx->mtx);
        ctx->state = NotifyContext::State::STOPPED;
        ctx->pendingCount = 0;
    }
    ctx->cv.notify_all();
    MEDIA_LOGI("StopBufferThread: 0x%{public}06" PRIXPTR " stopped.", FAKE_POINTER(this));
}

void ScreenCapBufferConsumerListener::Stop()
{
    StopBufferThread();
    consumer_->UnregisterConsumerListener();
}

void ScreenCapBufferConsumerListener::SetCallback(const std::shared_ptr<ScreenCaptureCallBack> &screenCaptureCb)
{
    std::lock_guard<std::mutex> lock(ctx_->mtx);
    ctx_->callback = screenCaptureCb;
}

ScreenCapBufferConsumerListener::~ScreenCapBufferConsumerListener()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Destroy.", FAKE_POINTER(this));
    std::unique_ptr<std::thread> thread;
    {
        std::lock_guard<std::mutex> lock(ctx_->mtx);
        ctx_->callback = nullptr;
        ctx_->state = NotifyContext::State::EXITING;
        ctx_->pendingCount = 0;
        thread = std::move(ctx_->thread);
    }
    ctx_->cv.notify_all();
    if (thread != nullptr && thread->joinable()) {
        if (thread->get_id() == std::this_thread::get_id()) {
            MEDIA_LOGW("0x%{public}06" PRIXPTR " stop buffer thread from itself, detach", FAKE_POINTER(this));
            thread->detach();
        } else {
            thread->join();
        }
    }
}

int32_t ScreenCapBufferConsumerListener::AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
    int64_t &timestamp, OHOS::Rect &damage)
{
    CHECK_AND_RETURN_RET_LOG(consumer_ != nullptr, MSERR_INVALID_OPERATION, "consumer is nullptr");
    {
        std::lock_guard<std::mutex> lock(ctx_->mtx);
        CHECK_AND_RETURN_RET_LOG(ctx_->IsRunning(), MSERR_INVALID_OPERATION, "buffer notify thread is stopped");
    }
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
        std::lock_guard<std::mutex> lock(ctx_->mtx);
        buf = ctx_->currentBuffer;
        ctx_->currentBuffer = surfaceBuffer;
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
        std::lock_guard<std::mutex> lock(ctx_->mtx);
        buf = ctx_->currentBuffer;
        ctx_->currentBuffer = nullptr;
    }
    CHECK_AND_RETURN_RET_LOG(buf != nullptr, MSERR_INVALID_OPERATION, "no video frame to release");
    CHECK_AND_RETURN_RET_LOG(consumer_ != nullptr, MSERR_INVALID_OPERATION, "consumer is nullptr");
    int32_t ret = consumer_->ReleaseBuffer(buf, -1); // -1 not wait
    CHECK_AND_RETURN_RET_LOG(ret == GSERROR_OK, MSERR_UNKNOWN, "ReleaseBuffer failed, ret:%{public}d", ret);
    return MSERR_OK;
}
} // namespace OHOS::Media
