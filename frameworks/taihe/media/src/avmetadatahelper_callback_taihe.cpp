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

#include <ani.h>
#include <sstream>
#include <iomanip>
#include "avmetadatahelper_callback_taihe.h"
#include "media_errors.h"
#include "media_log.h"
#include "scope_guard.h"
#include "event_queue.h"
#include "media_taihe_utils.h"
#include "pixel_map_taihe.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "AVMetadataHelperCallback"};
}

namespace ANI {
namespace Media {

AVMetadataHelperCallback::~AVMetadataHelperCallback()
{
    helper_ = nullptr;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void AVMetadataHelperCallback::setHelper(const std::shared_ptr<OHOS::Media::AVMetadataHelper> &helper)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(helper != nullptr, "AVMetadataHelper is nullptr");
    helper_ = helper;
}

void AVMetadataHelperCallback::SaveCallbackReference(const std::string &name, std::shared_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
}

void AVMetadataHelperCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    return;
}

void AVMetadataHelperCallback::OnInfo(OHOS::Media::HelperOnInfoType type,
    int32_t extra, const OHOS::Media::Format &infoBody)
{
    return;
}

void AVMetadataHelperCallback::OnPixelComplete(OHOS::Media::HelperOnInfoType type,
                                               const std::shared_ptr<OHOS::Media::AVBuffer> &reAvbuffer_,
                                               const ::OHOS::Media::FrameInfo &info,
                                               const OHOS::Media::PixelMapParams &param)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("OnPixelComplete is called, OnPixelCompleteType: %{public}d", type);
    CHECK_AND_RETURN_LOG(type == OHOS::Media::HelperOnInfoType::HELPER_INFO_TYPE_PIXEL, "HelperOnInfoType Error");
    CHECK_AND_RETURN_LOG(helper_ != nullptr, "helper_ is nullptr");
    auto pixelMap = helper_->ProcessPixelMap(reAvbuffer_, param, OHOS::Media::FrameScaleMode::ASPECT_RATIO);
    this->SendPixelCompleteCallback(info, pixelMap);
}

void AVMetadataHelperCallback::SendPixelCompleteCallback(const ::OHOS::Media::FrameInfo &info,
    const std::shared_ptr<::OHOS::Media::PixelMap> &pixelMap)
{
    if (refMap_.find(AVMetadataHelperEvent::EVENT_PIXEL_COMPLETE) == refMap_.end()) {
        MEDIA_LOGW("can not find pixelcomplete callback!");
        return;
    }
    AVMetadataJsCallback *cb = new(std::nothrow) AVMetadataJsCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVMetadataHelperEvent::EVENT_PIXEL_COMPLETE);
    cb->callbackName = AVMetadataHelperEvent::EVENT_PIXEL_COMPLETE;
    cb->requestedTimeUs = info.requestedTimeUs;
    cb->actualTimeUs = info.actualTimeUs;
    cb->fetchResult = static_cast<FetchResult>(info.fetchResult);
    cb->pixel_ = pixelMap;
    cb->errorCode = info.err;
    MEDIA_LOGI("AVMetadataHelperCallback::SendPixelCompleteCallback cb->errorCode, %{public}d", cb->errorCode);
    switch (info.err) {
        case OHOS::Media::OPERATION_NOT_ALLOWED:
            cb->errorMs = "OPERATION_NOT_ALLOWED";
            break;
        case OHOS::Media::FETCH_TIMEOUT:
            cb->errorMs = "FETCH_TIMEOUT";
            break;
        case OHOS::Media::UNSUPPORTED_FORMAT:
            cb->errorMs = "UNSUPPORTED_FORMAT";
            break;
        default:
            cb->errorMs = "NO_ERR";
    };
    this->OnJsPixelCompleteCallback(cb);
}

void AVMetadataHelperCallback::OnJsPixelCompleteCallback(AVMetadataJsCallback *jsCb) const
{
    CHECK_AND_RETURN_LOG(jsCb != nullptr, "jsCb is nullptr");
    std::string request = jsCb->callbackName;
    std::shared_ptr<AutoRef> ref = jsCb->autoRef;
    CHECK_AND_RETURN_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
        
    auto result = ohos::multimedia::media::FetchResult::key_t::FETCH_FAILED;
    switch (jsCb->fetchResult) {
        case FETCH_FAILED:
            result = ohos::multimedia::media::FetchResult::key_t::FETCH_FAILED;
            break;
        case FETCH_SUCCEEDED:
            result = ohos::multimedia::media::FetchResult::key_t::FETCH_SUCCEEDED;
            break;
        case FETCH_CANCELLED:
            result = ohos::multimedia::media::FetchResult::key_t::FETCH_CANCELLED;
            break;
    };

    ani_env *env = taihe::get_env();
    ::ohos::multimedia::media::FrameInfo frameInfo = {
        jsCb->requestedTimeUs,
        taihe::optional<int64_t>(std::in_place_t{}, jsCb->actualTimeUs),
        optional<::ohos::multimedia::image::image::PixelMap>(std::in_place_t{},
        Image::PixelMapImpl::CreatePixelMap(jsCb->pixel_)),
        result
    };

    taihe::optional<uintptr_t> err = std::nullopt;
    if (jsCb->errorCode != 0) {
        err = taihe::optional<uintptr_t>(std::in_place_t{}, reinterpret_cast<uintptr_t>(
            MediaTaiheUtils::ToBusinessError(env, jsCb->errorCode, jsCb->errorMs)));
    }

    auto func = ref->callbackRef_;
    CHECK_AND_RETURN_LOG(func != nullptr, "failed to get callback");

    std::shared_ptr<taihe::callback<void(::ohos::multimedia::media::FrameInfo const& frameInfo,
        taihe::optional_view<uintptr_t>)>> cacheCallback = std::reinterpret_pointer_cast
        <taihe::callback<void(::ohos::multimedia::media::FrameInfo const& frameInfo,
        taihe::optional_view<uintptr_t>)>>(func);
        (*cacheCallback)(frameInfo, taihe::optional<uintptr_t>(err));
}
} // namespace ANI
} // namespace OHOS