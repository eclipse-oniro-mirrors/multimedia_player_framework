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

#ifndef NATIVE_AV_META_DATA_HELPER_CALLBACK_H
#define NATIVE_AV_META_DATA_HELPER_CALLBACK_H

#include <mutex>

#include "avmetadatahelper.h"
#include "image_source.h"

namespace NativeAVMetadataHelperEvent {
const std::string EVENT_PIXEL_COMPLETE = "onFrameFetched";
}

namespace OHOS {
namespace Media {

struct NativeCallbackOnInfo {
    FrameInfo frameInfo;
    std::shared_ptr<PixelMap> pixelMap;
};


class BaseCallback {
public:
    virtual ~BaseCallback() = default;
    virtual void OnInfo(const NativeCallbackOnInfo &info) = 0;
};

class NativeAVMetadataHelperCallback : public HelperCallback {
public:
    explicit NativeAVMetadataHelperCallback() = default;
    virtual ~NativeAVMetadataHelperCallback() = default;

    void OnError(int32_t errorCode, const std::string &errorMsg) override;
    void OnInfo(HelperOnInfoType type, int32_t extra, const Format &infoBody) override;
    void OnPixelComplete (HelperOnInfoType type,
                        const std::shared_ptr<AVBuffer> &reAvbuffer_,
                        const FrameInfo &info,
                        const PixelMapParams &param) override;

    void SetHelper(const std::shared_ptr<AVMetadataHelper> &helper);
    void SaveCallbackReference(const std::string &name, std::shared_ptr<BaseCallback> ref);
    void ClearCallbackReference();

private:
    void SendPixelCompleteCallback(const FrameInfo &info, const std::shared_ptr<PixelMap> &pixelMap);

    std::mutex mutex_;
    std::shared_ptr<AVMetadataHelper> helper_ = nullptr;
    std::map<std::string, std::shared_ptr<BaseCallback>> refMap_;
};

}
}

#endif // NATIVE_AV_META_DATA_HELPER_CALLBACK_H