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

#include "screen_capture_local_surface.h"
#include "media_errors.h"
#include "media_log.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureLocalSurface"};
}

namespace OHOS {
namespace Media {

ScreenCaptureLocalSurface::~ScreenCaptureLocalSurface()
{
    sptr<OHOS::Surface> consumer;
    sptr<OHOS::Surface> producerSurface;
    sptr<ScreenCapBufferConsumerListener> surfaceCb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        consumer = std::move(consumer_);
        producerSurface = std::move(producerSurface_);
        surfaceCb = std::move(surfaceCb_);
    }
    if (consumer != nullptr) {
        consumer->UnregisterConsumerListener();
    }
}

int32_t ScreenCaptureLocalSurface::Init(const std::shared_ptr<ScreenCaptureCallBack> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(consumer_ == nullptr, MSERR_INVALID_OPERATION,
        "ScreenCaptureLocalSurface already initialized");

    consumer_ = OHOS::Surface::CreateSurfaceAsConsumer();
    CHECK_AND_RETURN_RET_LOG(consumer_ != nullptr, MSERR_UNKNOWN, "CreateSurfaceAsConsumer failed");
    consumer_->SetDefaultUsage(BUFFER_USAGE_CPU_READ | BUFFER_USAGE_MEM_MMZ_CACHE | BUFFER_USAGE_VENDOR_PRI8);

    auto producer = consumer_->GetProducer();
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, MSERR_UNKNOWN, "GetProducer failed");
    producerSurface_ = OHOS::Surface::CreateSurfaceAsProducer(producer);
    CHECK_AND_RETURN_RET_LOG(producerSurface_ != nullptr, MSERR_UNKNOWN, "CreateSurfaceAsProducer failed");

    surfaceCb_ = OHOS::sptr<ScreenCapBufferConsumerListener>::MakeSptr(consumer_, callback);
    CHECK_AND_RETURN_RET_LOG(surfaceCb_ != nullptr, MSERR_UNKNOWN, "MakeSptr surfaceCb_ failed");
    sptr<IBufferConsumerListener> listener = surfaceCb_;
    consumer_->RegisterConsumerListener(listener);

    int32_t ret = surfaceCb_->StartBufferThread();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "start buffer thread failed");
    return MSERR_OK;
}

void ScreenCaptureLocalSurface::SetCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback)
{
    sptr<ScreenCapBufferConsumerListener> cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = surfaceCb_;
    }
    if (cb != nullptr) {
        cb->SetCallback(callback);
    }
}

sptr<Surface> ScreenCaptureLocalSurface::GetProducerSurface() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return producerSurface_;
}

int32_t ScreenCaptureLocalSurface::AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
    int64_t &timestamp, OHOS::Rect &damage)
{
    sptr<ScreenCapBufferConsumerListener> cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = surfaceCb_;
    }
    if (cb == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return cb->AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage);
}

int32_t ScreenCaptureLocalSurface::ReleaseVideoBuffer()
{
    sptr<ScreenCapBufferConsumerListener> cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = surfaceCb_;
    }
    if (cb == nullptr) {
        return MSERR_INVALID_OPERATION;
    }
    return cb->ReleaseVideoBuffer();
}
} // namespace Media
} // namespace OHOS
