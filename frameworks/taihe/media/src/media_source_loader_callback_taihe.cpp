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

#include "media_source_loader_callback_taihe.h"
#include "buffer/avsharedmemory.h"
#include "media_dfx.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_source_loading_request_taihe.h"
#include "loading_request.h"
#include "scope_guard.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaSourceLoaderCallback"};
}

using namespace OHOS::Media;

namespace ANI {
namespace Media {
MediaDataSourceLoaderTaiheCallback::~MediaDataSourceLoaderTaiheCallback()
{
    isExit_ = true;
    cond_.notify_all();
}

void MediaDataSourceLoaderTaiheCallback::WaitResult()
{
    std::unique_lock<std::mutex> lock(mutexCond_);
    if (!setResult_) {
        static constexpr int32_t timeout = 200;
        cond_.wait_for(lock, std::chrono::milliseconds(timeout), [this]() { return setResult_ || isExit_; });
        if (!setResult_) {
            uuid_ = 0;
            if (isExit_) {
                MEDIA_LOGW("Reset, OPen has been cancel!");
            } else {
                MEDIA_LOGW("timeout 200ms!");
            }
        }
    }
    setResult_ = false;
}

MediaSourceLoaderCallback::MediaSourceLoaderCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaSourceLoaderCallback::~MediaSourceLoaderCallback()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int64_t MediaSourceLoaderCallback::Open(std::shared_ptr<LoadingRequest> &request)
{
    MediaTrace trace("MediaSourceLoaderCallback::open");
    MEDIA_LOGI("<< open");
    std::lock_guard<std::mutex> lock(mutex_);

    if (refMap_.find(FunctionName::SOURCE_OPEN) == refMap_.end()) {
        MEDIA_LOGE("can not find read callback!");
        return 0;
    }

    taiheCb_ = std::make_shared<MediaDataSourceLoaderTaiheCallback>();
    CHECK_AND_RETURN_RET_LOG(taiheCb_ != nullptr, 0, "cb is nullptr");
    taiheCb_->autoRef_ = refMap_.at(FunctionName::SOURCE_OPEN);
    taiheCb_->callbackName_ = FunctionName::SOURCE_OPEN;
    taiheCb_->request_ = request;

    MEDIA_LOGD("CallBack %{public}s start", taiheCb_->callbackName_.c_str());
    do {
        std::shared_ptr<AutoRef> ref = taiheCb_->autoRef_.lock();
        CHECK_AND_RETURN_RET_LOG(ref != nullptr, 0, "%{public}s AutoRef is nullptr", taiheCb_->callbackName_.c_str());
        auto func = ref->callbackRef_;

        std::shared_ptr<taihe::callback<
            double(::ohos::multimedia::media::weak::MediaSourceLoadingRequest)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<double
            (::ohos::multimedia::media::weak::MediaSourceLoadingRequest)>>(func);
        taiheCb_->uuid_ = (*cacheCallback)(static_cast<
            ::ohos::multimedia::media::weak::MediaSourceLoadingRequest>(
            MediaSourceLoadingRequestImpl::CreateLoadingRequest(taiheCb_->request_)));
        std::unique_lock<std::mutex> lock(taiheCb_->mutexCond_);
        taiheCb_->setResult_ = true;
        taiheCb_->cond_.notify_all();
    } while (0);
    taiheCb_->WaitResult();
    MEDIA_LOGI("MediaSourceLoaderCallback open out");
    return taiheCb_->uuid_;
}

void MediaSourceLoaderCallback::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    MediaTrace trace("MediaSourceLoaderCallback::read, uuid: " + std::to_string(uuid) +
        " offset: " + std::to_string(requestedOffset) + " Length:" + std::to_string(requestedLength));
    MEDIA_LOGI("<< read");
    std::lock_guard<std::mutex> lock(mutex_);

    if (refMap_.find(FunctionName::SOURCE_READ) == refMap_.end()) {
        MEDIA_LOGE("can not find read callback!");
        return;
    }

    taiheCb_ = std::make_shared<MediaDataSourceLoaderTaiheCallback>();
    CHECK_AND_RETURN_LOG(taiheCb_ != nullptr, "cb is nullptr");

    taiheCb_->autoRef_ = refMap_.at(FunctionName::SOURCE_READ);
    taiheCb_->callbackName_ = FunctionName::SOURCE_READ;
    taiheCb_->uuid_ = uuid;
    taiheCb_->requestedOffset_ = requestedOffset;
    taiheCb_->requestedLength_ = requestedLength;

    MEDIA_LOGD("CallBack %{public}s start", taiheCb_->callbackName_.c_str());
    do {
        std::shared_ptr<AutoRef> ref = taiheCb_->autoRef_.lock();
        MEDIA_LOGD("CallBack %{public}s start", taiheCb_->callbackName_.c_str());
        auto func = ref->callbackRef_;
        std::shared_ptr<taihe::callback<void(double, double, double)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(double, double, double)>>(func);
        (*cacheCallback)(static_cast<double>(taiheCb_->uuid_), static_cast<double>(taiheCb_->requestedOffset_),
            static_cast<double>(taiheCb_->requestedLength_));
    } while (0);
}

void MediaSourceLoaderCallback::Close(int64_t uuid)
{
    MediaTrace trace("MediaSourceLoaderCallback::close, uuid: " + std::to_string(uuid));
    MEDIA_LOGI("<< close");
    std::lock_guard<std::mutex> lock(mutex_);

    if (refMap_.find(FunctionName::SOURCE_CLOSE) == refMap_.end()) {
        MEDIA_LOGE("can not find read callback!");
        return;
    }

    taiheCb_ = std::make_shared<MediaDataSourceLoaderTaiheCallback>();
    CHECK_AND_RETURN_LOG(taiheCb_ != nullptr, "cb is nullptr");

    taiheCb_->autoRef_ = refMap_.at(FunctionName::SOURCE_CLOSE);
    taiheCb_->callbackName_ = FunctionName::SOURCE_CLOSE;
    taiheCb_->uuid_ = uuid;

    MEDIA_LOGD("CallBack %{public}s start", taiheCb_->callbackName_.c_str());
    do {
        std::shared_ptr<AutoRef> ref = taiheCb_->autoRef_.lock();
        MEDIA_LOGD("CallBack %{public}s start", taiheCb_->callbackName_.c_str());
        auto func = ref->callbackRef_;
        std::shared_ptr<taihe::callback<void(double)>> cacheCallback =
            std::reinterpret_pointer_cast<taihe::callback<void(double)>>(func);
        (*cacheCallback)(static_cast<double>(taiheCb_->uuid_));
    } while (0);
}

void MediaSourceLoaderCallback::SaveCallbackReference(const std::string &name, std::shared_ptr<AutoRef> ref)
{
    MEDIA_LOGI("Add Callback: %{public}s", name.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
}

void MediaSourceLoaderCallback::ClearCallbackReference()
{
    MEDIA_LOGI("ClearCallbackReference");
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, std::shared_ptr<AutoRef>> temp;
    temp.swap(refMap_);
    MEDIA_LOGI("callback has been clear");
    if (taiheCb_) {
        taiheCb_->isExit_ = true;
        taiheCb_->cond_.notify_all();
    }
}
} // namespace Media
} // namespace ANI