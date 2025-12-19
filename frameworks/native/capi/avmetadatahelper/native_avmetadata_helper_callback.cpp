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

#include "media_dfx.h"
#include "media_log.h"
#include "native_avmetadata_helper_callback.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "NativeAVMetadataHelperCallback"};
}

namespace OHOS {
namespace Media {

void NativeAVMetadataHelperCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MEDIA_LOGE("OnError:errorCode %{public}d, errorMsg %{public}s", errorCode, errorMsg.c_str());
}

void NativeAVMetadataHelperCallback::OnInfo(HelperOnInfoType type, int32_t extra, const Format &infoBody)
{
    MEDIA_LOGI("OnInfo is called, HelperOnInfoType: %{public}d, extra: %{public}d", type, extra);
}

void NativeAVMetadataHelperCallback::OnPixelComplete (HelperOnInfoType type,
    const std::shared_ptr<AVBuffer> &reAvbuffer_, const FrameInfo &info, const PixelMapParams &param)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("OnPixelComplete is called, OnPixelCompleteType: %{public}d", type);
    CHECK_AND_RETURN_LOG(type == HelperOnInfoType::HELPER_INFO_TYPE_PIXEL, "HelperOnInfoType Error");
    CHECK_AND_RETURN_LOG(helper_ != nullptr, "helper_ is nullptr");
    auto pixelMap = helper_->ProcessPixelMap(reAvbuffer_, param, FrameScaleMode::ASPECT_RATIO);
    SendPixelCompleteCallback(info, pixelMap);
}

void NativeAVMetadataHelperCallback::SendPixelCompleteCallback(const FrameInfo &info,
    const std::shared_ptr<PixelMap> &pixelMap)
{
    if (refMap_.find(NativeAVMetadataHelperEvent::EVENT_PIXEL_COMPLETE) == refMap_.end()) {
        MEDIA_LOGW("can not find pixelcomplete callback: %{public}s!",
            NativeAVMetadataHelperEvent::EVENT_PIXEL_COMPLETE.c_str());
        return;
    }
    auto callback = refMap_.at(NativeAVMetadataHelperEvent::EVENT_PIXEL_COMPLETE);
    NativeCallbackOnInfo param {
        .frameInfo = info,
        .pixelMap = pixelMap
    };
    callback->OnInfo(param);
}

void NativeAVMetadataHelperCallback::SetHelper(const std::shared_ptr<AVMetadataHelper> &helper)
{
    std::lock_guard<std::mutex> lock(mutex_);
    helper_ = helper;
}

void NativeAVMetadataHelperCallback::SaveCallbackReference(const std::string &name, std::shared_ptr<BaseCallback> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("SaveCallbackReference is called, name: %{public}s", name.c_str());
    refMap_[name] = ref;
}

void NativeAVMetadataHelperCallback::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ClearCallbackReference is called");
    refMap_.clear();
}

}
}
